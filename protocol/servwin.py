from asyncio import StreamReader, StreamWriter

from Crypto.Hash import SHA512
from Crypto.PublicKey.ECC import EccKey
from Crypto.Signature import eddsa
from construct import Struct, Int32ub, Int16ub

from protocol import ED25519_KEY_SIZE_BYTES, ED25519_EDDSA_SIZE_BYTES, kex
from protocol.transport import TCPTransport
from protocol.util import import_raw_ed25519_public_key

MIN_EXPIRE_SECONDS = 1800  # 30 mins


# TODO: Enhance exception raises

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


async def query(rw: tuple[StreamReader, StreamWriter],
                priv_key: EccKey, host_pub_key: EccKey | None) -> (int, list[int], tuple[bytes, bytes]):
    r, w = rw

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


async def feed(rw: tuple[StreamReader, StreamWriter],
               priv_key: EccKey, accepted_keys: list[EccKey],
               sec_til_expire: int, ports: list[int]) -> tuple[bytes, bytes, int]:
    r, w = rw

    k1, k2 = await kex.server_to_client(rw, priv_key)
    tp = TCPTransport(rw, k1, k2, None)
    data = await tp.recv()
    if len(data) != ED25519_KEY_SIZE_BYTES + ED25519_EDDSA_SIZE_BYTES:
        raise ValueError("Bad service window query format")
    peer_pub_key_bytes = data[:ED25519_KEY_SIZE_BYTES]
    peer_sign = data[-ED25519_EDDSA_SIZE_BYTES:]

    peer_pub_key = import_raw_ed25519_public_key(peer_pub_key_bytes)
    verifier = eddsa.new(peer_pub_key, mode="rfc8032")
    h = SHA512.new(k1 + k2 + peer_pub_key.export_key(format="raw")).digest()
    verifier.verify(h, peer_sign)

    if not peer_pub_key in accepted_keys:
        raise RuntimeError("Authenticate failed: client public key not in allow list")

    await tp.sendall(build(sec_til_expire, ports))

    return k1, k2, sec_til_expire
