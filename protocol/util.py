from asyncio import StreamReader

from Crypto.PublicKey import ECC


async def recv_full(r: StreamReader, count):
    data = b''
    while len(data) < count:
        data += r.readexactly(count - len(data))
    return data


def timingsafe_bcmp(a: bytes, b: bytes) -> bool:
    assert len(a) == len(b)
    res = 0
    for i in range(len(a)):
        res |= a[i] ^ b[i]
    return res == 0


def import_raw_ed25519_public_key(b: bytes):
    x, y = ECC._import_ed25519_public_key(b)
    return ECC.construct(curve="Ed25519", point_x=x, point_y=y)
