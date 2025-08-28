from __future__ import annotations

import argparse
import asyncio
import logging
import socket
import sys
from asyncio import Task, CancelledError
from datetime import datetime, timedelta
from typing import Literal, Callable

import config
import log
import udp
from protocol.transport import NonceManager, UDPPacket
from udp import AsyncSocket
from util import join_host_port


def init(obj, name):
    obj.config = None

    parser = argparse.ArgumentParser(
        prog=name,
        description="PyProject 2025"
    )

    parser.add_argument("-c", "--config")
    parser.add_argument("-v", "--verbose", nargs="?", const="INFO")
    parser.add_argument("-l", "--log")

    args = parser.parse_args()

    verbosity = None

    if args.verbose:
        try:
            verbosity = args.verbose.upper()
            logging.root.setLevel(verbosity)
        except Exception as e:
            logging.warning(f"Invalid verbosity: {e}")

    obj.config = config.load(args.config, name)
    if verbosity is None:
        try:
            verbosity = obj.config.verbosity.upper()
            logging.root.setLevel(verbosity)
        except Exception as e:
            logging.warning(f"Invalid verbosity: {e}")

    try:
        logging.root = log.setup(name, args.log, verbosity)
    except Exception as e:
        logging.error("Failed to set up logger.", exc_info=True)
        sys.exit(1)


class UDPSession:
    s_server_host: udp.AsyncSocket | None = None # Socket to py225d server or target host
    s_app_client: udp.AsyncSocket # Socket to application or py225 client
    app_client_addr: tuple[str, int]
    server_host_addr: tuple[str, int] | None = None
    side: Literal["client", "server"]
    k1: bytes
    k2: bytes
    nonce_mng: NonceManager
    expire: datetime
    timer_task: Task | None = None
    relay_task: Task | None = None

    @property
    def app_addr(self) -> tuple[str, int]:
        assert self.side == "client"
        return self.app_client_addr

    @property
    def client_addr(self) -> tuple[str, int]:
        assert self.side == "server"
        return self.app_client_addr

    @property
    def server_addr(self) -> tuple[str, int]:
        assert self.side == "client"
        return self.server_host_addr

    @property
    def host_addr(self) -> tuple[str, int]:
        assert self.side == "server"
        return self.server_host_addr

    @property
    def s_app(self) -> AsyncSocket:
        assert self.side == "client"
        return self.s_app_client

    @property
    def s_client(self) -> AsyncSocket:
        assert self.side == "server"
        return self.s_app_client

    @property
    def s_server(self) -> AsyncSocket:
        assert self.side == "client"
        return self.s_server_host

    @property
    def s_host(self) -> AsyncSocket:
        assert self.side == "server"
        return self.s_server_host

    def __init__(self, side: Literal["client", "server"],
                 s_app_client: udp.AsyncSocket,
                 k1: bytes, k2: bytes, nonce: NonceManager,
                 close_callback: Callable[[UDPSession], None]):
        self.side = side
        self.s_app_client = s_app_client
        self.app_client_addr = s_app_client.get_extra_info("peername")
        self.k1 = k1
        self.k2 = k2
        self.nonce_mng = nonce
        self.close_cb = close_callback

        self.server_or_host = "server" if side == "client" else "host"
        self.app_or_client = "app" if side == "client" else "client"

    def on_session_close(self):
        self.relay_task and self.relay_task.cancel()
        self.timer_task and self.timer_task.cancel()
        self.s_server_host and self.s_server_host.close()
        self.close_cb(self)

    async def timer(self):
        first_run = True
        ts = self.expire
        while first_run or ts != self.expire:
            first_run = False
            ts = self.expire
            await asyncio.sleep((ts - datetime.now()).total_seconds())

        # Session expired
        self.on_session_close()

    async def relay(self):
        """
        Relay UDP from server to application.
        """
        while True:
            try:
                d, a = await self.s_server_host.recvfrom()
            except CancelledError:
                return
            except Exception:
                logging.exception(f"Receive UDP packet from {self.server_or_host} {join_host_port(self.server_host_addr)} "
                                  f"for {self.app_or_client} {join_host_port(self.app_client_addr)} failed.", exc_info=True)
                return

            if self.server_host_addr != a:
                continue

            if self.side == "client":
                try:
                    p = UDPPacket(d, self.k1, self.k2, self.nonce_mng)
                    data = p.parse()
                except Exception as e:
                    logging.warning(f"Parse UDP packet from server {join_host_port(self.server_host_addr)} "
                                    f"for app {join_host_port(self.app_client_addr)} failed: {e}")
                    continue
            else:
                p = UDPPacket(d, self.k1, self.k2, self.nonce_mng)
                data = p.build()

            self.expire = datetime.now() + timedelta(minutes=5)
            try:
                self.s_app_client.sendto(data, self.app_client_addr)
            except Exception:
                logging.error(f"Send UDP packet to {join_host_port(self.app_client_addr)} failed.", exc_info=True)
                self.on_session_close()
                return

    def send(self, data: bytes):
        """
        Caller's responsibility to handle and log exceptions, but clean up is done by ``UDPSession``.
        """
        p = UDPPacket(data, self.k1, self.k2, self.nonce_mng)

        d = p.build()
        try:
            self.s_server_host.sendto(d, self.server_host_addr)
        except Exception:
            self.on_session_close()
            raise
        self.expire = datetime.now() + timedelta(minutes=5)

    async def connect(self, addr: tuple[str, int]):
        try:
            self.s_server_host = await udp.open_connection(remote_addr=addr)
            self.server_host_addr = self.s_server_host.get_extra_info("peername")
            self.timer_task = asyncio.create_task(self.timer())
            self.relay_task = asyncio.create_task(self.relay())
        except Exception:
            self.on_session_close()
            raise
