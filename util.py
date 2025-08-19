import asyncio

from socket import socket
from protocol.transport import TCPTransport

async def relay_s2t(s: socket, t: TCPTransport):
