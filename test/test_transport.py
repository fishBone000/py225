import os
import random
import socket
import unittest
from typing import final

from protocol.transport import TCPTransport, NonceManager
from protocol.kex import CHACHA20_KEY_SIZE_BYTES

def make_tcp_transport_pair():
    (s1, s2) = socket.socketpair()
    m1 = NonceManager.new("tcp")
    m2 = NonceManager.new("tcp")
    k1 = os.urandom(CHACHA20_KEY_SIZE_BYTES)
    k2 = os.urandom(CHACHA20_KEY_SIZE_BYTES)

    t1 = TCPTransport(s1, k1, k2, m1)
    t2 = TCPTransport(s2, k1, k2, m2)

    return (t1, t2), (s1, s2), (k1, k2), (m1, m2)

class TestTransport(unittest.TestCase):
    def test_tcp(self):
        ((t1, t2), (s1, s2), (k1, k2), (m1, m2)) = make_tcp_transport_pair()

        try:
            for i in range(1000):
                with self.subTest(i=i):
                    data = os.urandom(1 + int(random.random()*10000))
                    t1.sendall(data)
                    buf = t2.recv()
                    self.assertEqual(data, buf)
        finally:
            s1.close()
            s2.close()