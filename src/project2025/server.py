from __future__ import annotations

import asyncio
import logging
import random
import sys
from asyncio import Task, create_task, StreamWriter, StreamReader
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import common
from . import config
from . import udp
from . import util
from .common import UDPSession
from .protocol import servwin
from .protocol.transport import TCPTransport, NonceManager, UDPPacket, TCP_TRANSPORT_DENY_MSG
from .util import join_host_port, conn_err_str, set_no_delay

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


class PortsManager:
    duration_range: list[int]
    ports_range: list[int]
    percent_range: list[float]

    py225d: Py225d
    tcp_tasks: dict[int, Task]
    udp_tasks: dict[int, Task]
    udp_sessions_by_client_addr: dict[tuple[str, int], UDPSession]
    udp_task_by_session: dict[UDPSession, Task]
    udp_sessions_by_task: dict[Task, set[UDPSession]]
    next_randomization: datetime
    next_ports: set[int] | None

    def __init__(self, py225d: Py225d):
        self.py225d = py225d
        self.duration_range = py225d.config.ports_lasting_duration_mins_range
        self.ports_range = py225d.config.listen_port_range
        self.percent_range = py225d.config.percent_of_open_ports_range
        self.tcp_tasks = dict()
        self.udp_tasks = dict()
        self.udp_sessions_by_client_addr = dict()
        self.udp_task_by_session = dict()
        self.udp_sessions_by_task = dict()

        self.next_ports = None

    async def run(self):
        await self.timer()

    def gen_random_ports(self):
        percent = random.uniform(*self.percent_range)
        num_ports = round(((self.ports_range[1] - self.ports_range[0] + 1) * percent))
        ports = [p for p in range(self.ports_range[0], self.ports_range[1] + 1)]
        ports = set(random.sample(ports, num_ports))
        return ports

    def get_open_ports(self) -> set[int]:
        return self.next_ports or set(self.tcp_tasks.keys())

    def is_in_transit(self) -> bool:
        return self.next_ports is not None

    async def timer(self):
        try:
            for p in self.gen_random_ports():
                self.tcp_tasks[p] = create_task(self.listen_tcp(p))
                self.udp_tasks[p] = create_task(self.listen_udp(p))

            while True:
                duration = random.uniform(*self.duration_range)
                self.next_randomization = ts = datetime.now() + timedelta(minutes=duration)

                await asyncio.sleep((ts - timedelta(minutes=30) - datetime.now()).total_seconds())

                self.next_ports = self.gen_random_ports()
                new = self.next_ports.difference(self.tcp_tasks.keys())
                for p in new:
                    self.tcp_tasks[p] = create_task(self.listen_tcp(p))
                    if p not in self.udp_tasks:
                        self.udp_tasks[p] = create_task(self.listen_udp(p))

                await asyncio.sleep(30 * 60)

                close = set(self.tcp_tasks.keys()).difference(self.next_ports)
                for p in close:
                    self.tcp_tasks[p].cancel()
                    # We don't cancel UDP task here, the tasks are cancelled when all bond UDP sessions ended.
                self.next_ports = None
        except Exception:
            logging.exception("Unexpected error occurred!")
            raise

    async def listen_tcp(self, port: int):
        cfg = self.py225d.config
        try:
            s = await asyncio.start_server(self.handle_tcp, cfg.listen_ip, port)
        except Exception:
            logging.exception(f"Open TCP port {port} for data inbound failed.")
            return

        try:
            async with s:
                await s.serve_forever()
        except Exception:
            logging.exception(f"Serve TCP port {port} failed.")
            return

    async def handle_tcp(self, r: StreamReader, w: StreamWriter):
        cfg = self.py225d.config
        ip, peer_port = w.get_extra_info("peername")
        our_ip, port = w.get_extra_info("sockname")
        set_no_delay(w)
        sess = self.py225d.sess_mng.get_session(ip)
        client_addr = join_host_port((ip, peer_port))
        logging.debug(f"New TCP connection from {client_addr} to {join_host_port((our_ip, port))}.")
        if sess is None:
            w.write(TCP_TRANSPORT_DENY_MSG)
            await w.drain()
            w.close()
            logging.warning(f"Denied TCP connection from {client_addr} to {join_host_port((our_ip, port))}: "
                            f"session not created for this IP.")
            return

        k1, k2 = sess.k1, sess.k2
        tp = TCPTransport((r, w), k1, k2, sess.tcp_mng)

        try:
            r1, w1 = await asyncio.open_connection(cfg.connect_host, cfg.connect_port)
        except ConnectionError as e:
            logging.warning(f"Connect to target host for client {client_addr} failed: {conn_err_str(e)}.")
            tp.close()
            return
        except Exception:
            logging.warning(f"Connect to target host for client {client_addr} failed.", exc_info=True)
            tp.close()
            return

        try:
            await util.relay((r1, w1), tp)
            logging.debug(f"Relay for client {join_host_port((ip, peer_port))} finished.")
        except ConnectionError as e:
            logging.warning(f"Relay for client {join_host_port((ip, peer_port))} failed: {conn_err_str(e)}.")
        except EOFError:
            logging.warning(f"Relay for client {join_host_port((ip, peer_port))} failed: EOF.")
        except Exception:
            logging.warning(f"Relay for client {join_host_port((ip, peer_port))} failed.", exc_info=True)
        finally:
            w.close()
            tp.close()

    def on_udp_session_close(self, sess: UDPSession):
        self.udp_sessions_by_client_addr.pop(sess.client_addr)
        task = self.udp_task_by_session.pop(sess)
        if task in self.udp_sessions_by_task:  # If the task is running
            sessions = self.udp_sessions_by_task[task]
            sessions.remove(sess)
            if len(sessions) == 0:  # If no sessions left for this task
                _, port = sess.s_client.get_extra_info("sockname")
                if port not in self.tcp_tasks.keys():  # If task stayed running because of previous unfinished sessions
                    task.cancel()  # Stop this task

    def close_udp_sessions_of_task(self, task: Task):
        sessions = self.udp_sessions_by_task[task]
        for s in sessions:
            s.on_session_close()

    async def listen_udp(self, port: int):
        cfg = self.py225d.config
        try:
            s = await udp.open_connection((cfg.listen_ip, port))
        except Exception:
            logging.exception(f"Open UDP port {port} for data inbound failed")
            return

        host_addr = (cfg.connect_host, cfg.connect_port)
        task = asyncio.current_task()
        assert task is not None
        self.udp_tasks[port] = task
        self.udp_sessions_by_task[task] = set()
        try:
            while True:
                try:
                    data, addr = await s.recvfrom()
                except Exception:
                    logging.exception(f"Listen UDP packet from client on port {port} failed.")
                    logging.error(f"All UDP sessions bond to {join_host_port((cfg.listen_ip, port))} will be closed.")
                    self.close_udp_sessions_of_task(task)
                    return

                plain = None

                udp_sess = self.udp_sessions_by_client_addr.get(addr)
                if udp_sess is None:
                    sess = self.py225d.sess_mng.get_session(addr[0])
                    if sess is None:
                        continue

                    p = UDPPacket(data, sess.k1, sess.k2, sess.udp_mng)
                    try:
                        plain = p.parse()
                    except Exception as e:
                        logging.warning(f"Parse UDP packet from client {join_host_port(addr)} failed: {e}")
                        continue

                    udp_sess = UDPSession("server", s, addr, sess.k1, sess.k2, sess.udp_mng, self.on_udp_session_close)
                    try:
                        await udp_sess.connect(host_addr)
                    except Exception:
                        logging.exception(
                            f"Open UDP socket to host {host_addr} for client {join_host_port(addr)} failed.")
                        return
                    else:
                        self.udp_sessions_by_task[task].add(udp_sess)
                        self.udp_sessions_by_client_addr[addr] = udp_sess
                        self.udp_task_by_session[udp_sess] = task

                if plain is None:
                    p = UDPPacket(data, udp_sess.k1, udp_sess.k2, udp_sess.nonce_mng)
                    try:
                        plain = p.parse()
                    except Exception as e:
                        logging.warning(f"Parse UDP packet from client {join_host_port(addr)} failed: {e}")
                        continue

                try:
                    udp_sess.send(plain)
                except Exception:
                    logging.exception(f"Send UDP packet for client {join_host_port(addr)} to host {host_addr} failed.")
                    logging.error(f"All UDP sessions bond to {join_host_port((cfg.listen_ip, port))} will be closed.")
                    self.close_udp_sessions_of_task(task)
                    return
        except asyncio.CancelledError:
            raise
        except:
            logging.exception(f"Unexpected error when relaying UDP packet on port {port}.")
            self.close_udp_sessions_of_task(task)
        finally:
            s.close()
            if port in self.udp_tasks:
                self.udp_tasks.pop(port)
            if task in self.udp_sessions_by_task:
                self.udp_sessions_by_task.pop(task)


class Py225d:
    sess_mng: SessionManager
    port_mng: PortsManager
    config: config.Server
    udp_sessions: dict[tuple[str, int], UDPSession]

    def __init__(self):
        common.init(self, NAME)
        if not isinstance(self.config, config.Server):
            logging.error("Bad config format.")
            sys.exit(1)

        self.sess_mng = SessionManager()
        self.port_mng = PortsManager(self)

    async def handle_serv_win_query(self, r: StreamReader, w: StreamWriter):
        addr = join_host_port(w.get_extra_info("peername"))
        set_no_delay(w)
        try:
            logging.info(f"Incoming service window query from {addr}.")

            ports = list(self.port_mng.get_open_ports())

            ts = self.port_mng.next_randomization
            servwin_min = timedelta(minutes=self.config.serv_win_duration_mins_range[0])
            # If there's enough time until next TCP ports shuffle,
            # or there's not enough time but transition has not started yet
            if (ts - datetime.now()) > servwin_min or not self.port_mng.is_in_transit():
                duration = (ts - datetime.now()).total_seconds()
            else:  # Else transition has begun
                duration = (self.port_mng.next_randomization - datetime.now()).total_seconds()

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

    async def run(self):
        logging.info("py225d start up")
        coros = [self.port_mng.run(), self.listen_serv_win_query()]
        await asyncio.gather(*coros)


def main():
    instance = Py225d()
    try:
        asyncio.run(instance.run())
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
