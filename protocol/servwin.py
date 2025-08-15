import socket
from Crypto.PublicKey.ECC import EccKey
from Crypto.Signature import eddsa
from Crypto.Hash import SHA512
import kex
from protocol.transport import NonceManager
from transport import TCPTransport
from construct import Struct, Int32ub, Array, Int16ub


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
    return r.sec_til_expire, r.ports


def query(host: str, port: int, priv_key: EccKey, host_pub_key: EccKey | None, nonce_mng: NonceManager) -> (int,
                                                                                                            list[int]):
    s = socket.create_connection((host, port), timeout=5)
    (k1, k2, host_pub_key) = kex.client_to_server(s, host_pub_key)
    tp = TCPTransport(s, k1, k2, nonce_mng)

    # Do authentication
    pub_key = priv_key.public_key()
    signer = eddsa.new(priv_key, mode="rfc8032")
    h = SHA512.new(k1 + k2 + pub_key.export_key(format="raw")).digest()
    sign = signer.sign(h)
    tp.sendall(pub_key.export_key(format="raw") + sign)

    data = tp.recv()
    return parse(data)
