from socket import socket

from Crypto.PublicKey import ECC


def recv_full(s: socket, count):
    data = b''
    while len(data) < count:
        data += s.recv(count - len(data))
    return data


def timingsafe_bcmp(a: bytes, b: bytes) -> bool:
    assert len(a) == len(b)
    res = 0
    for i in range(len(a)):
        res |= a[i] ^ b[i]
    return res is 0


def import_raw_ed25519_public_key(b: bytes):
    x, y = ECC._import_ed25519_public_key(b)
    return ECC.construct(curve="Ed25519", point_x=x, point_y=y)