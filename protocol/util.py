from socket import socket


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