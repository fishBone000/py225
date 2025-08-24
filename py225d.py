from __future__ import annotations

import asyncio
import logging
import random
import sys
from asyncio import Task, create_task, StreamWriter, StreamReader
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import common
import config
import util
from protocol import servwin
from protocol.transport import TCPTransport, NonceManager
from util import join_host_port

NAME = "py225d"


@dataclass
class Session:
    k1: bytes
    k2: bytes
    expire: datetime
    tcp_mng: NonceManager = field(default_factory=lambda: NonceManager.new("tcp"))
    udp_mng: NonceManager = field(default_factory=lambda: NonceManager.new("udp"))
    timer_task: Task | None = None


class SessionManager:
    sessions: dict[str, Session]

    def __init__(self):
        self.sessions = dict()

    async def timer(self, ip: str, sess: Session):
        await asyncio.sleep((sess.expire - datetime.now()).total_seconds())
        if self.sessions[ip] is sess:
            self.sessions.pop(ip)

    def new_sess(self, ip: str, sess: Session):
        old_session = self.sessions.get(ip)
        if old_session is not None:
            old_session.timer_task.cancel()

        sess.timer_task = create_task(self.timer(ip, sess))
        self.sessions[ip] = sess

    def get_session(self, ip) -> Session | None:
        return self.sessions.get(ip)


class TCPPortsManager:
    duration_range: list[int]
    ports_range: list[int]
    percent_range: list[float]

    py225d: Py225d
    listen_tasks: dict[int, Task]
    timer_task: Task
    next_randomization: datetime
    next_ports: set[int] | None

    def __init__(self, py225d: Py225d):
        self.py225d = py225d
        self.duration_range = py225d.config.ports_lasting_duration_mins_range
        self.ports_range = py225d.config.listen_port_range
        self.percent_range = py225d.config.percent_of_open_ports_range

        self.listen_tasks = dict()
        self.next_ports = None

    async def start(self):
        self.timer_task = create_task(self.timer())

    def gen_random_ports(self):
        percent = random.uniform(*self.percent_range)
        num_ports = round(((self.ports_range[1] - self.ports_range[0] + 1) * percent))
        ports = [p for p in range(self.ports_range[0], self.ports_range[1] + 1)]
        ports = set(random.sample(ports, num_ports))
        return ports

    def get_open_ports(self) -> set[int]:
        return set(self.listen_tasks.keys())

    def is_in_transit(self) -> bool:
        return self.next_ports is not None

    async def timer(self):
        try:
            for p in self.gen_random_ports():
                self.listen_tasks[p] = create_task(self.py225d.listen_tcp(p))

            while True:
                duration = random.uniform(*self.duration_range)
                self.next_randomization = ts = datetime.now() + timedelta(minutes=duration)

                await asyncio.sleep((ts - timedelta(minutes=30) - datetime.now()).total_seconds())

                self.next_ports = self.gen_random_ports()
                new = self.next_ports.difference(self.listen_tasks.keys())
                for p in new:
                    self.listen_tasks[p] = create_task(self.py225d.listen_tcp(p))

                await asyncio.sleep(30 * 60)

                close = set(self.listen_tasks.keys()).difference(self.next_ports)
                for p in close:
                    self.listen_tasks[p].cancel()
                self.next_ports = None
        except Exception as e:
            logging.error("Unexpected error occurred!", exc_info=True)
            raise


class Py225d:
    sess_mng: SessionManager
    tcp_mng: TCPPortsManager
    config: config.Server

    def __init__(self):
        common.init(self, NAME)
        if not isinstance(self.config, config.Server):
            logging.error("Bad config format.")
            sys.exit(1j)

        self.sess_mng = SessionManager()
        self.tcp_mng = TCPPortsManager(self)

    async def handle_serv_win_query(self, r: StreamReader, w: StreamWriter):
        addr = join_host_port(w.get_extra_info("peername"))
        try:
            logging.info(f"Incoming service window query from {addr}.")

            ports = list(self.tcp_mng.get_open_ports())

            ts = self.tcp_mng.next_randomization
            servwin_min = timedelta(minutes=self.config.serv_win_duration_mins_range[0])
            # If there's enough time until next TCP ports shuffle,
            # or there's not enough time but transition has not started yet
            if (ts - datetime.now()) > servwin_min or not self.tcp_mng.is_in_transit():
                duration = (ts - datetime.now()).total_seconds()
            else:  # Else transition has begun
                duration = (self.tcp_mng.next_randomization - datetime.now()).total_seconds()

            k1, k2, exp = await servwin.feed((r, w), self.config.private_key, self.config.accepted_keys, int(duration),
                                             ports)
            exp_ts = datetime.now() + timedelta(seconds=exp)
            ip, _ = w.get_extra_info("peername")
            self.sess_mng.new_sess(ip, Session(k1, k2, exp_ts))
        except Exception:
            logging.error(f"Reply service window query to client {addr} failed.", exc_info=True)
            raise
        finally:
            w.close()
            await w.wait_closed()

    async def listen_serv_win_query(self):
        try:
            s = await asyncio.start_server(self.handle_serv_win_query, self.config.listen_ip, self.config.serv_win_port)
        except Exception:
            addr = join_host_port((self.config.listen_ip, self.config.serv_win_port))
            logging.error(f"Listen service window query at {addr} failed.", exc_info=True)
            raise

        try:
            async with s:
                await s.serve_forever()
        except Exception:
            addr = join_host_port((self.config.listen_ip, self.config.serv_win_port))
            logging.error(f"Listen service window query at {addr} failed.", exc_info=True)
            raise

    async def listen_tcp(self, port: int):
        try:
            s = await asyncio.start_server(self.handle_tcp, self.config.listen_ip, port)
        except Exception:
            logging.error(f"Open TCP port {port} for data inbound failed", exc_info=True)
            raise

        try:
            async with s:
                await s.serve_forever()
        except Exception:
            logging.error(f"Serve TCP port {port} failed.", exc_info=True)
            raise

    async def handle_tcp(self, r: StreamReader, w: StreamWriter):
        ip, peer_port = w.get_extra_info("peername")
        _, port = w.get_extra_info("sockname")
        sess = self.sess_mng.get_session(ip)
        if sess is None:
            w.close()
            logging.warning(f"Denied data connection from {join_host_port((ip, peer_port))} to port {port}: "
                            f"session not created for this IP.")
            await w.wait_closed()
            return

        k1, k2 = sess.k1, sess.k2
        tp = TCPTransport((r, w), k1, k2, sess.tcp_mng)

        try:
            r1, w1 = await asyncio.open_connection(self.config.connect_host, self.config.connect_port)
        except Exception:
            logging.warning(f"Connect to target host failed", exc_info=True)
            await tp.close()
            return

        try:
            await util.relay((r1, w1), tp)
            logging.debug(f"Relay for client {join_host_port((ip, peer_port))} finished.")
        except Exception:
            logging.warning(f"Relay for client {join_host_port((ip, peer_port))} failed.", exc_info=True)
            raise
        finally:
            w.close()
            await tp.close()
            await w.wait_closed()

    async def run(self):
        coros = [self.tcp_mng.start(), self.listen_serv_win_query()]
        await asyncio.gather(*coros)


if __name__ == '__main__':
    instance = Py225d()
    try:
        asyncio.run(instance.run())
    except KeyboardInterrupt:
        pass
