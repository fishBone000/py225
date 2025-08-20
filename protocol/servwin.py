from asyncio import open_connection

from Crypto.Hash import SHA512
from Crypto.PublicKey.ECC import EccKey
from Crypto.Signature import eddsa
from construct import Struct, Int32ub, Int16ub

import kex
from transport import TCPTransport

MIN_EXPIRE_SECONDS = 1800  # 30 mins


def get_struct(num_ports):
    return Struct(
        "sec_til_expire" / Int32ub,
        "ports" / Int16ub[num_ports]
    )


def build(sec_til_expire: int, ports: list[int]) -> bytes:
    s = get_struct(len(ports))
    return s.build({"sec_til_expire": sec_til_expire, "ports": ports})


def parse(data: bytes) -> (int, list[int]):
    sz = len(data)
    num_ports = int((sz - 4) / 2)
    if (sz - 4) % 2:
        raise ValueError("bad format")
    r = get_struct(num_ports).parse(data)
    if r.sec_til_expire <= MIN_EXPIRE_SECONDS:
        raise ValueError(f"expire time too short (<= {MIN_EXPIRE_SECONDS} secs)")
    return r.sec_til_expire, r.ports


async def query(addr: tuple[str, int],
                priv_key: EccKey, host_pub_key: EccKey | None) -> (int, list[int], tuple[bytes, bytes]):
    r, w = await open_connection(addr[0], addr[1], timeout=5)

    (k1, k2, host_pub_key) = await kex.client_to_server((r, w), host_pub_key)
    tp = TCPTransport((r, w), k1, k2, None)

    # Do authentication
    pub_key = priv_key.public_key()
    signer = eddsa.new(priv_key, mode="rfc8032")
    h = SHA512.new(k1 + k2 + pub_key.export_key(format="raw")).digest()
    sign = signer.sign(h)
    await tp.sendall(pub_key.export_key(format="raw") + sign)

    data = await tp.recv()
    (exp, ports) = parse(data)

    return exp, ports, k1, k2, host_pub_key
