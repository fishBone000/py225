import os
from socket import socket

from Crypto.Cipher import AES, ChaCha20
from Crypto.Hash import Poly1305

from protocol.util import recv_full, timingsafe_bcmp

CHACHA20_NONCE_SIZE_BYTES = 12
POLY1305_KEY_SIZE_BYTES = 32
AES_BLOCK_SIZE_BYTES = 16
POLY1305_TAG_SIZE_BYTES = 16
CHACHA20_MAX_NONCE = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF
HEADER_SIZE_BYTES = 4


class SecurityError(Exception):
    pass

# TODO: mem operation can be optimized, e.g. r/w on single bytearray instance?
class TCPTransport:
    def __init__(self, s: socket, k_1: bytes, k_2: bytes):
        if len(k_1) is not CHACHA20_NONCE_SIZE_BYTES or len(k_2) is not CHACHA20_NONCE_SIZE_BYTES:
            raise ValueError(f"size of k_1 and k_2 must be {CHACHA20_NONCE_SIZE_BYTES} bytes")
        self.s = s
        self.k_1 = k_1
        self.k_2 = k_2
        self.snd_nonce = None
        self.rcv_nonce = None
        self.broken = False

    def sendall(self, b: bytes):
        if len(b) > 0xFFFFFFFF:
            raise ValueError("packet too large")
        if self.broken:
            raise RuntimeError("broken transport")

        data = b''
        # If it's the first packet, generate a nonce and send encrypted nonce first
        if self.snd_nonce is None:
            buf = os.urandom(AES_BLOCK_SIZE_BYTES)
            self.snd_nonce = int.from_bytes(buf[:CHACHA20_NONCE_SIZE_BYTES], byteorder="little", signed=False)
            aes = AES.new(self.k_1, mode=AES.MODE_ECB)
            data += aes.encrypt(buf)

        # Encrypt the packet
        nonce_buf = self.snd_nonce.to_bytes(CHACHA20_NONCE_SIZE_BYTES, byteorder="big", signed=False)
        header_chacha = ChaCha20.new(self.k_1, nonce_buf)
        data_chacha = ChaCha20.new(self.k_2, nonce_buf)

        data += header_chacha.encrypt(len(b).to_bytes(HEADER_SIZE_BYTES, byteorder="big"))
        data += data_chacha.encrypt(b)
        data += Poly1305.new(self.k_2, ChaCha20, nonce_buf, data).digest()

        try:
            self.s.sendall(data)
        except:
            self.broken = True
            raise

        self.snd_nonce = (self.snd_nonce + 1) & CHACHA20_MAX_NONCE

    def recv(self) -> bytes:
        if self.broken:
            raise RuntimeError("broken transport")

        ciphertext = b''
        # If it's the first packet, receive encrypted nonce first
        if self.rcv_nonce is None:
            try:
                buf = recv_full(self.s, AES_BLOCK_SIZE_BYTES)
            except:
                self.broken = True
                raise
            ciphertext += buf
            aes = AES.new(self.k_1, mode=AES.MODE_ECB)
            buf = aes.decrypt(buf)
            self.rcv_nonce = int.from_bytes(buf[:CHACHA20_NONCE_SIZE_BYTES], byteorder="little", signed=False)

        nonce_buf = self.rcv_nonce.to_bytes(CHACHA20_NONCE_SIZE_BYTES, byteorder="big", signed=False)
        header_chacha = ChaCha20.new(self.k_1, nonce_buf)
        try:
            header = recv_full(self.s, HEADER_SIZE_BYTES)
        except:
            self.broken = True
            raise
        ciphertext += header
        packet_sz = int.from_bytes(header_chacha.decrypt(header), byteorder="big", signed=False)

        try:
            data = recv_full(self.s, packet_sz + POLY1305_TAG_SIZE_BYTES)
        except:
            self.broken = True
            raise
        payload = data[:packet_sz]
        tag = data[packet_sz:]
        ciphertext += payload

        expected_tag = Poly1305.new(self.k_2, ChaCha20, nonce_buf, ciphertext).digest()
        if not timingsafe_bcmp(tag, expected_tag):
            self.broken = True
            self.s.close()
            raise SecurityError("tag mismatch")

        data_chacha = ChaCha20.new(self.k_2, nonce_buf)
        plain = data_chacha.decrypt(payload)
        self.rcv_nonce = (self.rcv_nonce+1) & CHACHA20_MAX_NONCE

        return plain