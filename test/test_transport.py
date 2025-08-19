import asyncio
import os
import random
import socket
import unittest
from typing import final

from protocol.transport import TCPTransport, NonceManager, UDPPacket
from protocol.kex import CHACHA20_KEY_SIZE_BYTES

def prepare_key_and_mng():
    m1 = NonceManager.new("tcp")
    m2 = NonceManager.new("tcp")
    k1 = os.urandom(CHACHA20_KEY_SIZE_BYTES)
    k2 = os.urandom(CHACHA20_KEY_SIZE_BYTES)
    return (m1, m2), (k1, k2)

async def make_tcp_transport_pair():
    (s1, s2) = socket.socketpair()

    ((m1, m2), (k1, k2)) = prepare_key_and_mng()

    t1 = TCPTransport(s1, k1, k2, m1)
    t2 = TCPTransport(s2, k1, k2, m2)
    await t1.prepare_async()
    await t2.prepare_async()

    return (t1, t2), (s1, s2), (k1, k2), (m1, m2)

class TestTransport(unittest.TestCase):
    def test_tcp(self):
        asyncio.run(self.do_test_tcp())

    async def do_test_tcp(self):
        ((t1, t2), (s1, s2), (k1, k2), (m1, m2)) = await make_tcp_transport_pair()

        try:
            for i in range(1000):
                with self.subTest(i=i):
                    data = os.urandom(1 + int(random.random()*10000))
                    await t1.sendall(data)
                    buf = await t2.recv()
                    self.assertEqual(data, buf)
        finally:
            t1.close()
            t2.close()

    def test_tcp_zero_nonce(self):
        asyncio.run(self.do_test_tcp_zero_nonce())

    async def do_test_tcp_zero_nonce(self):
        (s1, s2) = socket.socketpair()

        k1 = os.urandom(CHACHA20_KEY_SIZE_BYTES)
        k2 = os.urandom(CHACHA20_KEY_SIZE_BYTES)

        t1 = TCPTransport(s1, k1, k2, None)
        t2 = TCPTransport(s2, k1, k2, None)
        await t1.prepare_async()
        await t2.prepare_async()

        try:
            for i in range(1000):
                with self.subTest(i=i):
                    data = os.urandom(1 + int(random.random()*10000))
                    await t1.sendall(data)
                    buf = await t2.recv()
                    self.assertEqual(data, buf)
        finally:
            t1.close()
            t2.close()

    def test_udp(self):
        ((m1, m2), (k1, k2)) = prepare_key_and_mng()

        for i in range(1000):
            with self.subTest(i=i):
                data = os.urandom(1 + int(random.random() * 10000))

                p1 = UDPPacket(data, k1, k2, m1)
                buf = p1.build()
                p2 = UDPPacket(buf, k1, k2, m2)

                self.assertEqual(p1.data, p2.parse())