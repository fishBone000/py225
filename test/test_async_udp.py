import asyncio
import os
import unittest

import udp


class TestAsyncSocket(unittest.TestCase):
    def test_async(self):
        asyncio.run(self.do_test_async())

    async def do_test_async(self):
        s1 = await udp.open_connection(("127.0.0.1", 0))
        s2 = await udp.open_connection(("127.0.0.1", 0))
        a1 = s1.getextrainfo("sockname")
        a2 = s2.getextrainfo("sockname")

        for i in range(1000):
            with self.subTest(i=i):
                data = os.urandom(1024)
                s1.sendto(data, a2)
                d1, a = await s2.recvfrom()
                self.assertEqual(data, d1)
                self.assertEqual(a1, a)

                s2.sendto(data, a1)
                d1, a = await s1.recvfrom()
                self.assertEqual(data, d1)
                self.assertEqual(a2, a)

        s1.close()
        s2.close()