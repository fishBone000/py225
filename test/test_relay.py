import asyncio
import os
import socket
import unittest

import util
from protocol import CHACHA20_KEY_SIZE_BYTES
from protocol.transport import NonceManager, TCPTransport


async def rwpair():
    s1, s2 = socket.socketpair()
    r1, w1 = await asyncio.open_connection(sock=s1)
    r2, w2 = await asyncio.open_connection(sock=s2)
    return r1, w1, r2, w2


class TestRelay(unittest.TestCase):
    def test_relay(self):
        asyncio.run(self.do_test_relay())

    async def do_test_relay(self):
        r_app, w_app, r_c_a, w_c_a = await rwpair()
        r_c_s, w_c_s, r_s_c, w_s_c = await rwpair()
        r_s_t, w_s_t, r_t, w_t = await rwpair()

        mng_c = NonceManager.new("tcp")
        mng_s = NonceManager.new("tcp")

        k1 = os.urandom(CHACHA20_KEY_SIZE_BYTES)
        k2 = os.urandom(CHACHA20_KEY_SIZE_BYTES)

        tp_c = TCPTransport((r_c_s, w_c_s), k1, k2, mng_c)
        tp_s = TCPTransport((r_s_c, w_s_c), k1, k2, mng_s)

        t_c = asyncio.create_task(util.relay((r_c_a, w_c_a), tp_c))
        t_s = asyncio.create_task(util.relay((r_s_t, w_s_t), tp_s))

        try:
            for i in range(1000):
                with self.subTest(i=i):
                    d = os.urandom(1024)
                    w_app.write(d)
                    await w_app.drain()
                    d1 = await r_t.readexactly(1024)
                    self.assertEqual(d, d1)

                    w_t.write(d)
                    await w_t.drain()
                    d1 = await r_app.readexactly(1024)
                    self.assertEqual(d, d1)
        finally:
            w_app.close()
            w_c_s.close()
            w_s_t.close()
            w_c_a.close()
            w_s_c.close()
            w_t.close()

            await w_app.wait_closed()
            await w_c_s.wait_closed()
            await w_s_t.wait_closed()
            await w_c_a.wait_closed()
            await w_s_c.wait_closed()
            await w_t.wait_closed()
