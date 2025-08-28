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
import udp
from common import UDPSession
from protocol import servwin
from protocol.transport import NonceManager, TCPTransport
from util import join_host_port, relay

NAME: Literal["py225"] = "py225"


class Session:
    type session_info = tuple[datetime, list[int], NonceManager, NonceManager, bytes, bytes]
    expire: datetime

    lock: Lock
    query_task: Task[session_info] | None
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
        self.query_task = None
        self.next_query_task = None

    def get(self) -> Task[session_info]:
        if self.query_task is None:
            self.query_task = create_task(self.query(), name=f"Query Task ({self.address})")
            return self.query_task
        else:
            if not self.query_task.done() or self.query_task.exception() is None and not self.expired():
                return self.query_task
            if self.next_query_task and (not self.next_query_task.done() or self.next_query_task.exception() is None):
                self.query_task = self.next_query_task
                self.next_query_task = None
                return self.query_task
            self.next_query_task = None
            self.query_task = create_task(self.query(), name=f"Query Task ({self.address})")
            return self.query_task

    async def query_once(self):
        """
        Main purpose of this function is to query the server once on client start up,
        but block exceptions raises in ``get`` function, because ``asyncio.gather(get())``
        will fail if ``get`` raises any exception.
        :return:
        """
        self.get()

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


class Server:
    def __init__(self, rec: config.ServerRecord):
        self.private_key = rec.private_key
        self.host_public_key = rec.host_public_key
        self.sess = Session((rec.host, rec.port), rec.private_key, rec.host_public_key)


class Py225:
    servers: dict[tuple[str, int], Server]
    tasks: set[Task]
    config: config.Client
    udp_sessions: dict[tuple[str, int], UDPSession]

    def __init__(self):
        self.servers = {}

        common.init(self, NAME)
        if not isinstance(self.config, config.Client):
            logging.error("Bad config format.")
            sys.exit(1)

        for rec in self.config.servers:
            self.servers[(rec.host, rec.port)] = Server(rec)

        self.udp_sessions = dict()

    async def listen_tcp(self):
        server = await asyncio.start_server(self.handle_tcp, self.config.listen_ip, self.config.listen_port)
        async with server:
            await server.serve_forever()

    def choose_server(self) -> tuple[Server, tuple[str, int]]:
        """
        For now only support 1 server
        """
        rec = self.config.servers[0]
        addr = (rec.host, rec.port)
        return self.servers[addr], addr

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
            rw2 = await asyncio.open_connection(host, port)
        except Exception:
            logging.warning(f"Failed to connect to server: {join_host_port((host, port))}", exc_info=True)
            w.close()
            await w.wait_closed()
            return

        tp = TCPTransport(rw2, k1, k2, mng)
        try:
            await relay((r, w), tp)
            logging.debug(f"Relay for TCP inbound {addr} finished.")
        except Exception:
            logging.warning(f"Error occurred while relaying "
                            f"from TCP inbound {addr} to server {join_host_port((host, port))}",
                            exc_info=True)
            raise
        finally:
            w.close()
            await tp.close()
            await w.wait_closed()

    def on_udp_session_close(self, sess: UDPSession):
        self.udp_sessions.pop(sess.app_addr)

    async def listen_udp(self):
        try:
            try:
                s = await udp.open_connection(local_addr=(self.config.listen_ip, self.config.listen_port))
            except Exception:
                logging.exception("Failed to open UDP socket for applications.")
                raise

            while True:
                d, addr = await s.recvfrom()
                sess = self.udp_sessions.get(addr)
                if sess is None:
                    server, server_addr = self.choose_server()
                    if not server.sess.get().done() or server.sess.get().exception():
                        continue
                    _, ports, _, nonce_mng, k1, k2 = await server.sess.get()
                    sess = UDPSession("client", s, addr, k1, k2, nonce_mng, self.on_udp_session_close)

                    try:
                        await sess.connect((server_addr[0], random.choice(ports)))
                    except Exception:
                        logging.exception(f"Failed to create UDP socket to server for client {join_host_port(addr)}.")
                        continue
                    else:
                        self.udp_sessions[addr] = sess

                try:
                    sess.send(d)
                except Exception:
                    logging.exception(f"Relay UDP packet from client {join_host_port(addr)} "
                                      f"to server {join_host_port(sess.server_addr)} failed.")

        except Exception:
            logging.exception("Unexpected error occured when listening UDP from applications.")
            raise

    async def run(self):
        logging.info("py225 start up")
        sess_queries = [self.servers[s].sess.query_once() for s in self.servers]
        aws = [self.listen_tcp(), self.listen_udp()] + sess_queries
        await asyncio.gather(*aws)


if __name__ == '__main__':
    instance = Py225()
    try:
        asyncio.run(instance.run())
    except KeyboardInterrupt:
        pass
