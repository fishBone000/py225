import asyncio
import socket
import unittest

from Crypto.PublicKey import ECC

from protocol import kex


class TestKex(unittest.TestCase):
    def test_kex(self):
        for i in range(1000):
            with self.subTest(i=i):
                asyncio.run(self.do_test_kex())

    async def do_test_kex(self):
        s1, s2 = socket.socketpair()
        r1, w1 = await asyncio.open_connection(sock=s1)
        r2, w2 = await asyncio.open_connection(sock=s2)

        k = ECC.generate(curve="Ed25519")
        async with asyncio.TaskGroup() as tg:
            tg.create_task(kex.client_to_server((r1, w1), k.public_key()))
            tg.create_task(kex.server_to_client((r2, w2), k))

        w1.close()
        w2.close()
        await w1.wait_closed()
        await w2.wait_closed()
