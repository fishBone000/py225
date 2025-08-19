import asyncio
import os
import threading
from asyncio import AbstractEventLoop, StreamReader, StreamWriter
from dataclasses import dataclass
from socket import socket

from Crypto.Cipher import AES, ChaCha20
from Crypto.Hash import Poly1305

from protocol.util import recv_full, timingsafe_bcmp
from protocol.kex import CHACHA20_KEY_SIZE_BYTES

CHACHA20_NONCE_SIZE_BYTES = 12
POLY1305_KEY_SIZE_BYTES = 32
AES_BLOCK_SIZE_BYTES = 16
POLY1305_TAG_SIZE_BYTES = 16
CHACHA20_MAX_NONCE = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF
HEADER_SIZE_BYTES = 4

TCP_NONCE_STEP_SZ = 2 ** 12
TCP_NONCE_STEPS = 2000


class SecurityError(Exception):
    pass


class NonceDepletedError(Exception):
    pass


class BadNonceError(Exception):
    pass


class NonceManager:
    def __init__(self, step_sz, steps):
        self.step_sz = step_sz
        self.steps = steps
        self.win_sz = step_sz * steps

        self.recv_upper = 0
        self.recv_set = {0}
        self.recv_lock = threading.Lock()

        self.send_lock = threading.Lock()
        self.next_send = 0

    def check_recv(self, n):
        with self.recv_lock:
            if n % self.step_sz != 0:
                raise ValueError("bad nonce")

            # If received nonce is outside the congestion window,
            # we need to update the window by updating recv_set
            if n > self.recv_upper:
                # If the new congestion window does not intersect with the old one
                if n - self.recv_upper > self.win_sz:
                    self.recv_set = {i for i in range(n - self.win_sz, n, self.step_sz)}
                else:
                    # Both window intersects with each other
                    recv_lower = self.recv_upper - self.win_sz
                    new_recv_lower = n - self.win_sz
                    # Remove nonces that are outside the window
                    for i in range(recv_lower, new_recv_lower, self.step_sz):
                        self.recv_set.discard(i)
                    # Add new nonces
                    for i in range(self.recv_upper + self.step_sz, n, self.step_sz):
                        self.recv_set.add(i)
                self.recv_upper = n
                return True

            # If received nonce is too old
            if n < max(0, self.recv_upper - self.steps * self.step_sz):
                return False

            # Received nonce falls in the congestion window
            try:
                self.recv_set.remove(n)
            except KeyError:
                return False
            return True

    def gen_send(self) -> int:
        with self.send_lock:
            nonce = self.next_send
            self.next_send += self.step_sz
            return nonce

    @classmethod
    def new(cls, mode):
        if mode not in ["udp", "tcp"]:
            raise ValueError("mode must be \"udp\" or \"tcp\"")

        if mode == "tcp":
            return NonceManager(TCP_NONCE_STEP_SZ, TCP_NONCE_STEPS)
        else:
            return NonceManager(1, 2000)


# TODO: mem operation can be optimized, e.g. r/w on single bytearray instance?
class TCPTransport:
    r: StreamReader | None
    w: StreamWriter | None

    def __init__(self, s: socket, k_1: bytes, k_2: bytes, mng: NonceManager | None):
        if len(k_1) is not CHACHA20_KEY_SIZE_BYTES or len(k_2) is not CHACHA20_KEY_SIZE_BYTES:
            raise ValueError(f"size of k_1 and k_2 must be {CHACHA20_KEY_SIZE_BYTES} bytes")
        self.s = s
        self.s.setblocking(False)
        self.r, self.w = None, None
        self.k_1 = k_1
        self.k_2 = k_2
        self.mng = mng
        if mng is None:
            self.snd_nonce = 0
            self.initial_snd_nonce = 0
            self.rcv_nonce = 0
            self.initial_rcv_nonce = 0
        else:
            self.snd_nonce = None
            self.initial_snd_nonce = None
            self.rcv_nonce = None
            self.initial_rcv_nonce = None
        self.broken = False

    async def prepare_async(self):
        self.r, self.w = await asyncio.open_connection(sock=self.s)

    async def sendall(self, b: bytes):
        if len(b) > 0xFFFFFFFF:
            raise ValueError("packet too large")
        if self.broken:
            raise RuntimeError("broken transport")
        if self.snd_nonce is not None and self.snd_nonce - self.initial_snd_nonce >= TCP_NONCE_STEP_SZ:
            self.broken = True
            self.s.close()
            raise NonceDepletedError
        if self.w is None:
            raise RuntimeError("transport not prepared for async, call prepare_async() first")

        data = b''
        # If it's the first packet, generate a nonce and send encrypted nonce first
        if self.snd_nonce is None:
            self.initial_snd_nonce = self.snd_nonce = self.mng.gen_send()
            aes = AES.new(self.k_1, mode=AES.MODE_ECB)
            nonce_buf = self.snd_nonce.to_bytes(CHACHA20_NONCE_SIZE_BYTES, byteorder="big")
            data += aes.encrypt(os.urandom(AES_BLOCK_SIZE_BYTES - CHACHA20_NONCE_SIZE_BYTES) + nonce_buf)
            data += Poly1305.new(key=self.k_1, cipher=ChaCha20, nonce=nonce_buf, data=data).digest()

            self.snd_nonce += 1

        begin_sign = len(data)

        # Encrypt the packet
        nonce_buf = self.snd_nonce.to_bytes(CHACHA20_NONCE_SIZE_BYTES, byteorder="big")
        header_chacha = ChaCha20.new(key=self.k_1, nonce=nonce_buf)
        data_chacha = ChaCha20.new(key=self.k_2, nonce=nonce_buf)

        data += header_chacha.encrypt(len(b).to_bytes(HEADER_SIZE_BYTES, byteorder="big"))
        data += data_chacha.encrypt(b)
        data += Poly1305.new(key=self.k_2, cipher=ChaCha20, nonce=nonce_buf, data=data[begin_sign:]).digest()

        try:
            self.w.write(data)
            await self.w.drain()
        except:
            self.broken = True
            raise

        self.snd_nonce += 1

    async def recv(self) -> bytes:
        if self.broken:
            raise RuntimeError("broken transport")
        if self.rcv_nonce is not None and self.rcv_nonce - self.initial_rcv_nonce >= TCP_NONCE_STEP_SZ:
            self.broken = True
            self.s.close()
            raise NonceDepletedError

        ciphertext = b''
        # If it's the first packet, receive encrypted nonce first
        if self.rcv_nonce is None:
            try:
                buf = await self.r.readexactly(AES_BLOCK_SIZE_BYTES + POLY1305_TAG_SIZE_BYTES)
            except:
                self.broken = True
                raise

            aes = AES.new(self.k_1, mode=AES.MODE_ECB)
            nonce_buf = aes.decrypt(buf[:AES_BLOCK_SIZE_BYTES])[-CHACHA20_NONCE_SIZE_BYTES:]
            tag = buf[-POLY1305_TAG_SIZE_BYTES:]
            expected = Poly1305.new(key=self.k_1, cipher=ChaCha20, nonce=nonce_buf,
                                    data=buf[:AES_BLOCK_SIZE_BYTES]).digest()
            if not timingsafe_bcmp(tag, expected):
                self.broken = True
                self.s.close()
                raise SecurityError("tag mismatch")

            nonce = int.from_bytes(nonce_buf, byteorder="big", signed=False)
            if not self.mng.check_recv(nonce):
                self.broken = True
                self.s.close()
                raise BadNonceError
            self.initial_rcv_nonce = self.rcv_nonce = nonce + 1

        nonce_buf = self.rcv_nonce.to_bytes(CHACHA20_NONCE_SIZE_BYTES, byteorder="big", signed=False)
        header_chacha = ChaCha20.new(key=self.k_1, nonce=nonce_buf)
        try:
            header = await self.r.readexactly(HEADER_SIZE_BYTES)
        except:
            self.broken = True
            raise
        ciphertext += header
        packet_sz = int.from_bytes(header_chacha.decrypt(header), byteorder="big", signed=False)

        try:
            data = await self.r.readexactly(packet_sz + POLY1305_TAG_SIZE_BYTES)
        except:
            self.broken = True
            raise
        payload = data[:packet_sz]
        tag = data[packet_sz:]
        ciphertext += payload

        expected_tag = Poly1305.new(key=self.k_2, cipher=ChaCha20, nonce=nonce_buf, data=ciphertext).digest()
        if not timingsafe_bcmp(tag, expected_tag):
            self.broken = True
            self.s.close()
            raise SecurityError("tag mismatch")

        data_chacha = ChaCha20.new(key=self.k_2, nonce=nonce_buf)
        plain = data_chacha.decrypt(payload)

        self.rcv_nonce += 1

        return plain

    def close(self):
        if self.w is not None:
            self.w.close()
        else:
            self.s.close()


@dataclass
class UDPPacket:
    data: bytes
    k1: bytes
    k2: bytes
    nonce_mng: NonceManager

    def build(self) -> bytes:
        nonce = self.nonce_mng.gen_send()
        buf = b""

        aes = AES.new(self.k1, mode=AES.MODE_ECB)
        nonce_buf = nonce.to_bytes(CHACHA20_NONCE_SIZE_BYTES, byteorder="big")
        buf += aes.encrypt(os.urandom(AES_BLOCK_SIZE_BYTES - CHACHA20_NONCE_SIZE_BYTES) + nonce_buf)

        data_chacha = ChaCha20.new(key=self.k2, nonce=nonce_buf)

        buf += data_chacha.encrypt(self.data)
        buf += Poly1305.new(key=self.k2, cipher=ChaCha20, nonce=nonce_buf, data=buf).digest()

        return buf

    def parse(self):
        if len(self.data) <= AES_BLOCK_SIZE_BYTES + POLY1305_TAG_SIZE_BYTES:
            raise ValueError("bad format")

        aes = AES.new(self.k1, mode=AES.MODE_ECB)
        nonce_buf = aes.decrypt(self.data[:AES_BLOCK_SIZE_BYTES])[-CHACHA20_NONCE_SIZE_BYTES:]
        nonce = int.from_bytes(nonce_buf, signed=False)

        tag = self.data[-POLY1305_TAG_SIZE_BYTES:]
        expected = Poly1305.new(key=self.k2, cipher=ChaCha20, nonce=nonce_buf,
                                data=self.data[:-POLY1305_TAG_SIZE_BYTES]).digest()
        if not timingsafe_bcmp(expected, tag):
            raise SecurityError("tag mismatch")

        if not self.nonce_mng.check_recv(nonce):
            raise BadNonceError

        chacha = ChaCha20.new(key=self.k2, nonce=nonce_buf)
        return chacha.decrypt(self.data[AES_BLOCK_SIZE_BYTES:-POLY1305_TAG_SIZE_BYTES])
