from __future__ import annotations

import argparse
import logging
import random
import socket
import sys
import threading
import time
from threading import Thread, Lock, Condition
from time import sleep
from typing import Literal
from datetime import datetime, timedelta

import yaml
from Crypto.PublicKey.ECC import EccKey

import config
import log
from protocol import kex, servwin
from protocol.transport import NonceManager, TCPTransport

NAME: Literal["py225"] = "py225"


class _Session(Thread):
    expire: datetime
    ports: list[int]
    tcp_nonce_mng: NonceManager
    udp_nonce_mng: NonceManager
    k1: bytes
    k2: bytes
    ready: bool

    lock: Lock
    on_updated: Condition
    shall_renew: Condition

    MAX_RETRIES = 5

    def __init__(self, address: tuple[str, int], private_key: EccKey, host_public_key: EccKey):
        super().__init__()
        self.ready = False
        self.address = address
        self.private_key = private_key
        self.host_public_key = host_public_key
        self.lock = Lock()
        self.on_updated = Condition()
        self.shall_renew = Condition()

    def get(self) -> tuple[list[int], NonceManager, NonceManager, bytes, bytes] | None:
        """
        Get session attributes
        :return: (ports, TCP nonce manager, UDP nonce manager, K1, K2)
        """
        with self.lock:
            if self.ready:
                return self.ports, self.tcp_nonce_mng, self.udp_nonce_mng, self.k1, self.k2
            else:
                self.shall_renew.notify_all()
                return None

    def wait_for_update(self, timeout):
        return self.on_updated.wait(timeout)

    def renew(self, expire: datetime, ports: list[int], k1: bytes, k2: bytes):
        with self.lock:
            self.expire = expire
            self.ports = ports
            self.k1 = k1
            self.k2 = k2
            self.tcp_nonce_mng = NonceManager.new("tcp")
            self.udp_nonce_mng = NonceManager.new("udp")

            self.ready = True

        threading.Thread(target=self.expire_timer).start()

        self.on_updated.notify_all()

    def expire_timer(self):
        with self.lock:
            k1 = self.k1
            k2 = self.k2
            exp = self.expire

        sleep((exp - timedelta(minutes=10) - datetime.now()).total_seconds())
        self.shall_renew.notify_all()

        # Subtract 5 seconds to make a safe margin
        renewed = self.wait_for_update((exp - datetime.now()).total_seconds() - 5)
        if not renewed:
            with self.lock:
                if k1 != self.k1 or k2 != self.k2:
                    self.ready = False
                    self.shall_renew.notify_all()

    def report_update_failed(self):
        with self.lock:
            if not self.ready:
                self.on_updated.notify_all()

    def run(self):
        self.query()

        while True:
            self.shall_renew.wait()
            self.query()

    def query(self):
        logging.info(f"Begin querying service window from {self.address[0]} port {self.address[1]}.")
        for retry in range(self.MAX_RETRIES + 1):
            try:
                (expire, ports, k1, k2, _) = servwin.query(self.address,
                                                           self.private_key,
                                                           self.host_public_key)
                logging.info(f"Query service window from {self.address[0]} port {self.address[1]} success")
            except (TimeoutError, EOFError) as e:
                if retry == self.MAX_RETRIES:
                    logging.error(f"Query service window from {self.address[0]} port {self.address[1]} failed: {e}. ")
                else:
                    logging.warning(f"Query service window from {self.address[0]} port {self.address[1]} failed: {e}. "
                                    f"Retrying: {retry + 1}/{self.MAX_RETRIES}")
            except:
                logging.error(f"Query service window from {self.address[0]} port {self.address[1]} failed.",
                              exc_info=True)
                break

    def start_worker_thread(self):
        self.start()


class _Server:
    def __init__(self, rec: config.ServerRecord):
        self.private_key = rec.private_key
        self.host_public_key = rec.host_public_key
        self.sess = _Session((rec.host, rec.port), rec.private_key, rec.host_public_key)
        self.sess.start_worker_thread()


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
