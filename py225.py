from __future__ import annotations

import asyncio
import logging
import random
import sys
from asyncio import Lock, create_task, Task, StreamReader, StreamWriter
from datetime import datetime, timedelta
from typing import Literal

from Crypto.PublicKey.ECC import EccKey

import common
import config
from protocol import servwin
from protocol.transport import NonceManager, TCPTransport
from util import join_host_port, relay

NAME: Literal["py225"] = "py225"


class _Session:
    type session_info = tuple[datetime, list[int], NonceManager, NonceManager, bytes, bytes]
    expire: datetime

    lock: Lock
    query_task: Task[session_info]
    next_query_task: Task[session_info] | None
    timer_task: Task

    MAX_RETRIES = 5

    def __init__(self, address: tuple[str, int], private_key: EccKey, host_public_key: EccKey):
        super().__init__()
        self.ready = False
        self.address = address
        self.private_key = private_key
        self.host_public_key = host_public_key
        self.lock = Lock()

    def get(self) -> Task[session_info]:
        if self.query_task is None:
            self.query_task = create_task(self.query(), name=f"Query Task ({self.address})")
            return self.query_task
        else:
            if not self.query_task.done() or self.query_task.exception() is None and not self.expired():
                return self.query_task
            if not self.next_query_task.done() or self.next_query_task.exception() is None:
                self.query_task = self.next_query_task
                self.next_query_task = None
                return self.query_task
            self.next_query_task = None
            self.query_task = create_task(self.query(), name=f"Query Task ({self.address})")
            return self.query_task

    def expired(self):
        assert self.query_task.done() and self.query_task.exception() is None
        return (datetime.now() - self.expire).total_seconds() >= 0

    async def expire_timer(self):
        exp = self.expire

        await asyncio.sleep((exp - timedelta(minutes=10) - datetime.now()).total_seconds())

        new_task = create_task(self.query(), name=f"Query Task ({self.address})")
        self.next_query_task = new_task

        await asyncio.sleep(60 * 5)

        if new_task.exception() is not None:
            new_task = create_task(self.query(), name=f"Query Task ({self.address})")
            self.next_query_task = new_task

    async def query(self) -> session_info:
        logging.info(f"Begin querying service window from {self.address[0]} port {self.address[1]}.")
        for retry in range(self.MAX_RETRIES + 1):
            try:
                r, w = await asyncio.open_connection(*self.address)
                (expire, ports, k1, k2, _) = await servwin.query((r, w),
                                                                 self.private_key,
                                                                 self.host_public_key)
                w.close()
                ts = datetime.now() + timedelta(seconds=expire)
                logging.info(f"Query service window from {self.address[0]} port {self.address[1]} success")

                zis_task = asyncio.current_task()
                assert zis_task is not None
                self.query_task = zis_task
                self.next_query_task = None
                self.expire = ts
                self.timer_task = create_task(self.expire_timer(), name="Expire Timer")

                await w.wait_closed()

                return ts, ports, NonceManager.new("tcp"), NonceManager.new("udp"), k1, k2
            except (TimeoutError, EOFError) as e:
                if retry == self.MAX_RETRIES:
                    logging.error(f"Query service window from {self.address[0]} port {self.address[1]} failed: {e}. ")
                    raise
                else:
                    logging.warning(f"Query service window from {self.address[0]} port {self.address[1]} failed: {e}. "
                                    f"Retrying: {retry + 1}/{self.MAX_RETRIES}")
            except:
                logging.error(f"Query service window from {self.address[0]} port {self.address[1]} failed.",
                              exc_info=True)
                raise

        # Code shouldn't reach here, add raise to please IDE
        raise RuntimeError("unexpected code path")


class _Server:
    def __init__(self, rec: config.ServerRecord):
        self.private_key = rec.private_key
        self.host_public_key = rec.host_public_key
        self.sess = _Session((rec.host, rec.port), rec.private_key, rec.host_public_key)
        self.sess.get()


class Py225:
    servers: dict[tuple[str, int], _Server]
    tasks: set[Task]
    config: config.Client

    def __init__(self):
        self.servers = {}

        common.init(self, NAME)
        if not isinstance(self.config, config.Client):
            logging.error("Bad config format")
            sys.exit(1)

        for rec in self.config.servers:
            self.servers[(rec.host, rec.port)] = _Server(rec)

    async def listen_tcp(self):
        server = await asyncio.start_server(self.handle_tcp, self.config.listen_ip, self.config.listen_port)
        async with server:
            await server.serve_forever()

    def choose_server(self) -> tuple[_Server, str]:
        """
        For now only support 1 server
        """
        rec = self.config.servers[0]
        addr = (rec.host, rec.port)
        return self.servers[addr], addr[0]

    async def handle_tcp(self, r: StreamReader, w: StreamWriter):
        addr = join_host_port(w.get_extra_info("peername"))
        logging.debug(f"Inbound TCP from {addr}")

        server, host = self.choose_server()
        try:
            res = await server.sess.get()
        except Exception:
            logging.warning(f"Closing TCP inbound {addr}, service window not ready")
            w.close()
            await w.wait_closed()
            return

        _, ports, mng, _, k1, k2 = res
        port = random.choice(ports)
        try:
            rw2 = await asyncio.open_connection(host, port, timeout=5)
        except Exception:
            logging.warning(f"Failed to connect to server: {join_host_port((host, port))}", exc_info=True)
            w.close()
            await w.wait_closed()
            return

        tp = TCPTransport(rw2, k1, k2, mng)
        try:
            await relay((r, w), tp)
        except Exception:
            logging.warning(f"Error occurred while relaying "
                            f"from client {addr} to server {join_host_port((host, port))}",
                            exc_info=True)
            raise
        finally:
            w.close()
            await tp.close()
            await w.wait_closed()

    def start(self):
        logging.info("py225 start up")
        sess_gets = [self.servers[s].sess.get() for s in self.servers]
        aws = [self.listen_tcp()] + sess_gets
        asyncio.gather(*aws)


if __name__ == '__main__':
    instance = Py225()
    instance.start()
