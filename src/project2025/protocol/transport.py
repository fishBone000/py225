import asyncio
import logging
import os
import socket
from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass
from typing import Literal

from Crypto.Cipher import AES, ChaCha20
from Crypto.Hash import Poly1305

from . import CHACHA20_NONCE_SIZE_BYTES, AES_BLOCK_SIZE_BYTES, POLY1305_TAG_SIZE_BYTES, CHACHA20_KEY_SIZE_BYTES
from .util import timingsafe_bcmp

HEADER_SIZE_BYTES = 4
TCP_TRANSPORT_MAX_SIZE_BYTES = 0xFFFFFFFF
TCP_NONCE_STEP_SZ = 2 ** 40
TCP_NONCE_STEPS = 2000
TCP_BEGIN_NONCE = 10
UDP_NONCE_STEP_SZ = 1
UDP_NONCE_STEPS = 2000
TCP_MAX_NONCE = 0x7FFFFFFF_FFFFFFFF_FFFFFFFF
UDP_BEGIN_NONCE = 0x80000000_00000000_00000000
UDP_MAX_NONCE = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF
TCP_TRANSPORT_DENY_MSG = b'\x00' * (AES_BLOCK_SIZE_BYTES + POLY1305_TAG_SIZE_BYTES)


class UnauthenticTagError(Exception):
    pass


class NonceDepletedError(Exception):
    pass


class BadNonceError(Exception):
    pass


class UnexpectedNonceError(Exception):
    pass


class FormatError(Exception):
    pass


class DeniedError(Exception):
    pass


class NonceManager:
    def __init__(self, step_sz, steps, begin_nonce, max_nonce):
        """
        It's not intended to call __init__ directly.
        Use ``NonceManager.new()`` instead.
        """
        self.step_sz = step_sz
        self.steps = steps
        self.win_sz = step_sz * steps

        self.recv_upper = begin_nonce
        self.recv_set = {begin_nonce}

        self.next_send = self.begin_nonce = begin_nonce
        self.max_nonce = max_nonce

    def check_recv(self, n):
        """
        Checks if received nonce is valid.
        :param n: The nonce.
        :return: None.
        :raises BadNonceError: If nonce is invalid.
        :raises UnexpectedNonceError: If the nonce is not expected to be received, e.g. it's not allowed in protocol.
        """
        assert n > 0
        if (n - self.begin_nonce) % self.step_sz != 0:
            raise UnexpectedNonceError
        if n > self.max_nonce or n < self.begin_nonce:
            raise UnexpectedNonceError

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
            return

        # If received nonce is too old
        if n < max(0, self.recv_upper - self.steps * self.step_sz):
            raise BadNonceError

        # Received nonce falls in the congestion window
        try:
            self.recv_set.remove(n)
        except KeyError:
            raise BadNonceError
        return

    def gen_send(self) -> int:
        """
        Generate a nonce for sending.
        :return: The nonce.
        :raises NonceDepletedError: If no more nonces are available.
        """
        nonce = self.next_send
        if nonce > self.max_nonce:
            raise NonceDepletedError
        self.next_send += self.step_sz
        return nonce

    @classmethod
    def new(cls, mode: Literal["udp", "tcp"]):
        """
        Creates a NonceManager instance.
        :param mode: Must be "udp" or "tcp".
        :return: NonceManager
        """
        assert mode in ["udp", "tcp"]

        if mode == "tcp":
            return NonceManager(TCP_NONCE_STEP_SZ, TCP_NONCE_STEPS, TCP_BEGIN_NONCE, TCP_MAX_NONCE)
        else:
            return NonceManager(UDP_NONCE_STEP_SZ, UDP_NONCE_STEPS, UDP_BEGIN_NONCE, UDP_MAX_NONCE)


# TODO: mem operation can be optimized, e.g. r/w on single bytearray instance?
class TCPTransport:
    r: StreamReader
    w: StreamWriter

    def __init__(self, rw: tuple[StreamReader, StreamWriter], k_1: bytes, k_2: bytes, mng: NonceManager | None):
        if len(k_1) is not CHACHA20_KEY_SIZE_BYTES or len(k_2) is not CHACHA20_KEY_SIZE_BYTES:
            raise ValueError(f"size of k_1 and k_2 must be {CHACHA20_KEY_SIZE_BYTES} bytes")
        self.r, self.w = rw

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

    def set_no_delay(self):
        s = self.w.get_extra_info("socket")

        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            logging.warning(f"Set no delay failed.", exc_info=True)


    async def sendall(self, b: bytes):
        """
        Sends data via TCP.
        :param b: Data.
        :raises ValueError: If data is too large, or zero sized.
        :raises RuntimeError: If the transport is broken, e.g. there was a previous error.
        :raises NonceDepletedError: If nonce is depleted for this TCP connection or client-server session.
        """
        if len(b) > TCP_TRANSPORT_MAX_SIZE_BYTES:
            raise ValueError("packet too large")
        if not b:
            raise ValueError("Packet size cannot be zero.")
        if self.broken:
            raise RuntimeError("broken transport")
        if self.snd_nonce is not None and self.snd_nonce - self.initial_snd_nonce >= TCP_NONCE_STEP_SZ:
            self.broken = True
            await self.close()
            raise NonceDepletedError

        data = b''
        # If it's the first packet, generate a nonce and send encrypted nonce first
        if self.snd_nonce is None:
            try:
                self.initial_snd_nonce = self.snd_nonce = self.mng.gen_send()
            except NonceDepletedError:
                self.broken = True
                await self.close()
                raise
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
        """
        Receives single packet.
        :return: Data in packet. Zero length ``bytes`` if EOF received.
        :raises RuntimeError: If transport is broken, e.g. there was a previous error.
        :raises FormatError: If received packet has zero length size.
        :raises NonceDepletedError: If nonce is depleted for this TCP connection or client-server session.
        :raises UnauthenticTagError: If tag in received packet is invalid.
        :raises asyncio.IncompleteReadError: If EOF received before receiving the whole packet
        :raises BadNonceError: If nonce is invalid.
        :raises UnexpectedNonceError: If received nonce is not expected, e.g. protocol doesn't allow it.
        :raises DeniedError: If peer denied the transport.
        """
        if self.broken:
            raise RuntimeError("broken transport")
        if self.rcv_nonce is not None and self.rcv_nonce - self.initial_rcv_nonce >= TCP_NONCE_STEP_SZ:
            self.broken = True
            await self.close()
            raise NonceDepletedError

        ciphertext = b''
        # If it's the first packet, receive encrypted nonce first
        if self.rcv_nonce is None:
            try:
                buf = await self.r.readexactly(AES_BLOCK_SIZE_BYTES + POLY1305_TAG_SIZE_BYTES)
            except:
                self.broken = True
                raise

            if buf == TCP_TRANSPORT_DENY_MSG:
                self.broken = True
                raise DeniedError

            aes = AES.new(self.k_1, mode=AES.MODE_ECB)
            nonce_buf = aes.decrypt(buf[:AES_BLOCK_SIZE_BYTES])[-CHACHA20_NONCE_SIZE_BYTES:]
            tag = buf[-POLY1305_TAG_SIZE_BYTES:]
            expected = Poly1305.new(key=self.k_1, cipher=ChaCha20, nonce=nonce_buf,
                                    data=buf[:AES_BLOCK_SIZE_BYTES]).digest()
            if not timingsafe_bcmp(tag, expected):
                self.broken = True
                await self.close()
                raise UnauthenticTagError

            nonce = int.from_bytes(nonce_buf, byteorder="big", signed=False)
            try:
                self.mng.check_recv(nonce)
            except (BadNonceError, UnexpectedNonceError):
                self.broken = True
                await self.close()
                raise
            self.initial_rcv_nonce = self.rcv_nonce = nonce + 1

        nonce_buf = self.rcv_nonce.to_bytes(CHACHA20_NONCE_SIZE_BYTES, byteorder="big", signed=False)
        header_chacha = ChaCha20.new(key=self.k_1, nonce=nonce_buf)
        try:
            header = await self.r.readexactly(HEADER_SIZE_BYTES)
        except asyncio.IncompleteReadError as e:
            if self.initial_rcv_nonce == self.rcv_nonce or e.partial:
                raise
            self.broken = True  # Transport is actually closed, setting as broken anyway
            return b""
        except Exception:
            self.broken = True
            raise

        ciphertext += header
        packet_sz = int.from_bytes(header_chacha.decrypt(header), byteorder="big", signed=False)
        if packet_sz == 0:
            self.broken = True
            await self.close()
            raise FormatError

        try:
            data = await self.r.readexactly(packet_sz + POLY1305_TAG_SIZE_BYTES)
        except Exception:
            self.broken = True
            raise
        payload = data[:packet_sz]
        tag = data[packet_sz:]
        ciphertext += payload

        expected_tag = Poly1305.new(key=self.k_2, cipher=ChaCha20, nonce=nonce_buf, data=ciphertext).digest()
        if not timingsafe_bcmp(tag, expected_tag):
            self.broken = True
            await self.close()
            raise UnauthenticTagError

        data_chacha = ChaCha20.new(key=self.k_2, nonce=nonce_buf)
        plain = data_chacha.decrypt(payload)

        self.rcv_nonce += 1

        return plain

    def close(self):
        self.w.close()


# TODO: Enhance exception handling for NonceManager in py225 and py225d
@dataclass
class UDPPacket:
    data: bytes
    k1: bytes
    k2: bytes
    nonce_mng: NonceManager

    def build(self) -> bytes:
        """
        Build the UDP packet based on provided attributes.

        The ``data`` attribute holds the plaintext and is not altered in the process.
        :return: The built packet.
        :raises NonceDepletedError: If nonce is depleted.
        """
        nonce = self.nonce_mng.gen_send()
        buf = b""

        aes = AES.new(self.k1, mode=AES.MODE_ECB)
        nonce_buf = nonce.to_bytes(CHACHA20_NONCE_SIZE_BYTES, byteorder="big")
        buf += aes.encrypt(os.urandom(AES_BLOCK_SIZE_BYTES - CHACHA20_NONCE_SIZE_BYTES) + nonce_buf)

        data_chacha = ChaCha20.new(key=self.k2, nonce=nonce_buf)

        buf += data_chacha.encrypt(self.data)
        buf += Poly1305.new(key=self.k2, cipher=ChaCha20, nonce=nonce_buf, data=buf).digest()

        return buf

    def parse(self) -> bytes:
        """
        Parses the UDP packet based on provided attributes.

        ``data`` attribute holds the whole packet and is not altered in the process.
        :return: The plaintext.
        :raises FormatError: If packet format is invalid.
        :raises UnauthenticTagError: If tag is invalid.
        :raises BadNonceError: If nonce is invalid.
        :raises UnexpectedNonceError: If nonce is not expected.
        """
        if len(self.data) <= AES_BLOCK_SIZE_BYTES + POLY1305_TAG_SIZE_BYTES:
            raise FormatError

        aes = AES.new(self.k1, mode=AES.MODE_ECB)
        nonce_buf = aes.decrypt(self.data[:AES_BLOCK_SIZE_BYTES])[-CHACHA20_NONCE_SIZE_BYTES:]
        nonce = int.from_bytes(nonce_buf, signed=False)

        tag = self.data[-POLY1305_TAG_SIZE_BYTES:]
        expected = Poly1305.new(key=self.k2, cipher=ChaCha20, nonce=nonce_buf,
                                data=self.data[:-POLY1305_TAG_SIZE_BYTES]).digest()
        if not timingsafe_bcmp(expected, tag):
            raise UnauthenticTagError

        self.nonce_mng.check_recv(nonce)

        chacha = ChaCha20.new(key=self.k2, nonce=nonce_buf)
        return chacha.decrypt(self.data[AES_BLOCK_SIZE_BYTES:-POLY1305_TAG_SIZE_BYTES])
