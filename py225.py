from __future__ import annotations

import argparse
import asyncio
import logging
import random
import socket
import sys
import threading
from datetime import datetime, timedelta
from time import sleep
from typing import Literal
from asyncio import Lock, create_task, Task

from Crypto.PublicKey.ECC import EccKey

import config
import log
from protocol import servwin
from protocol.transport import NonceManager, TCPTransport

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

        await asyncio.sleep(60*5)

        if new_task.exception() is not None:
            new_task = create_task(self.query(), name=f"Query Task ({self.address})")
            self.next_query_task = new_task

    async def query(self) -> session_info:
        logging.info(f"Begin querying service window from {self.address[0]} port {self.address[1]}.")
        for retry in range(self.MAX_RETRIES + 1):
            try:
                (expire, ports, k1, k2, _) = await servwin.query(self.address,
                                                                 self.private_key,
                                                                 self.host_public_key)
                ts = datetime.now() + timedelta(seconds=expire)
                logging.info(f"Query service window from {self.address[0]} port {self.address[1]} success")

                zis_task = asyncio.current_task()
                assert zis_task is not None
                self.query_task = zis_task
                self.next_query_task = None
                self.expire = ts
                self.timer_task = create_task(self.expire_timer(), name="Expire Timer")

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

    def __init__(self):
        self.config = None
        self.servers = {}

        parser = argparse.ArgumentParser(
            prog=NAME,
            description="PyProject 2025"
        )

        parser.add_argument("-c", "--config", nargs=1)
        parser.add_argument("-v", "--verbose", nargs="?", const="info", default="warning")
        parser.add_argument("-l", "--log", nargs=1)

        args = parser.parse_args()

        if args.verbose:
            try:
                logging.root.setLevel(args.verbose)
            except Exception as e:
                logging.warning(f"Invalid verbosity: {e}")

        self.config = config.load(args.config, NAME)
        if not args.verbose:
            try:
                logging.root.setLevel(self.config.verbosity)
            except Exception as e:
                logging.warning(f"Invalid verbosity: {e}")

        try:
            logging.root = log.setup(NAME, args.log, args.verbose or self.config.verbosity)
        except Exception as e:
            logging.error(e)
            sys.exit(1)

        for rec in self.config.servers:
            self.servers[(rec.host, rec.port)] = _Server(rec)

    def listen_tcp(self):
        with socket.create_server((self.config.listen_ip, self.config.listen_port)) as listener:
            while True:
                s, addr = listener.accept()
                logging.debug(f"New inbound TCP from {addr[0]}:{addr[1]}")
                threading.Thread(target=self.handle_tcp, args=(s,)).start()

    def choose_server(self) -> tuple[_Server, str]:
        """
        For now only support 1 server
        """
        rec = self.config.servers[0]
        addr = (rec.host, rec.port)
        return self.servers[addr], addr[0]

    def handle_tcp(self, s: socket.socket):
        server, host = self.choose_server()
        res = server.sess.get()
        if res is None:
            logging.warning(f"Closing TCP inbound {s.getpeername()}, service window not ready")
            s.close()
            return

        ports, mng, _, k1, k2 = res
        port = random.choice(ports)
        try:
            with socket.create_connection((host, port), 5) as out:
                t = TCPTransport(out, k1, k2, mng)
        except:
            pass

    def start(self):
        logging.info("py225 start up")


if __name__ == '__main__':
    instance = Py225()
    instance.start()
