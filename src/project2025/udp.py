import asyncio
import socket
from asyncio import DatagramProtocol, DatagramTransport
from typing import Any


class AsyncSocket(DatagramProtocol):
    transport: DatagramTransport | None
    exc: Exception | None

    def __init__(self):
        self.transport = None
        self.queue = asyncio.Queue()
        self.exc = None

    def connection_made(self, transport: DatagramTransport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.queue.put_nowait((data, addr))

    async def recvfrom(self) -> tuple[bytes, tuple[str, int]]:
        assert self.transport is not None, "Socket not opened"
        if self.exc:
            raise self.exc
        return await self.queue.get()

    def sendto(self, data: bytes, addr: tuple[str, int]):
        assert self.transport is not None, "Socket not opened"
        if self.exc:
            raise self.exc
        self.transport.sendto(data, addr)

    def get_extra_info(self, name: str, default: Any | None = None):
        assert self.transport is not None, "Socket not opened"
        return self.transport.get_extra_info(name, default)

    def close(self):
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    def connection_lost(self, exc):
        self.exc = exc
        self.queue.shutdown()
        self.transport = None


async def open_connection(local_addr: tuple[str, int] | None = None,
                          remote_addr: tuple[str, int] | None = None) -> AsyncSocket:
    loop = asyncio.get_running_loop()
    _, s = await loop.create_datagram_endpoint(AsyncSocket, local_addr, remote_addr, family=socket.AF_INET)
    return s
