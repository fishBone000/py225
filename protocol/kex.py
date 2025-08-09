import base64
import socket
import os
from Crypto.Cipher import ChaCha20
from Crypto.Hash import Poly1305, SHA512
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256, SHA512
from Crypto.Signature import eddsa

CHACHA20_KEY_SIZE_BYTES = 32
CHACHA20_POLY1305_KEY_SIZE_BYTES = 64
ED25519_KEY_SIZE_BYTES = 32
ED25519_ECDSA_SIZE_BYTES = 64
SHA256_SIZE_BYTES = 32
SHA512_SIZE_BYTES = 64


class KexError(Exception):
    pass


def _recv_full(s: socket.socket, count):
    data = b''
    while len(data) < count:
        data += s.recv(count - len(data))
    return data


def _import_raw_ed25519_public_key(b: bytes):
    x, y = ECC._import_ed25519_public_key(b)
    return ECC.construct(curve="Ed25519", point_x=x, point_y=y)


def client_to_server(s: socket.socket, host_public_key: bytes | None):
    """
    Performs X25519 from client side
    :param s: TCP connection to remote host.
    :param host_public_key: Public key of remote host
    :return: (k_1, k_2, host_pub_key), where derived_key is a tuple of 2 256 bits byte string.
    :raises KexError: If signature is invalid or public keys sent by remote host is invalid
    """
    eph_priv = ECC.generate(curve="ed25519")
    q_c = eph_priv.public_key()
    s.sendall(q_c.export_key(format="DER"))

    # K_S, Q_S, signature on hash
    resp = _recv_full(s, 2 * ED25519_KEY_SIZE_BYTES + ED25519_ECDSA_SIZE_BYTES)
    try:
        k_s = _import_raw_ed25519_public_key(resp[:ED25519_KEY_SIZE_BYTES])
    except ValueError as e:
        raise KexError("bad host public key format") from e
    if host_public_key is not None and host_public_key != resp[:ED25519_KEY_SIZE_BYTES]:
        raise KexError("incorrect host public key").add_note(
            f"received raw host key is: {base64.b64encode(resp[:ED25519_KEY_SIZE_BYTES])}")

    try:
        q_s = _import_raw_ed25519_public_key(resp[ED25519_KEY_SIZE_BYTES:2 * ED25519_KEY_SIZE_BYTES])
    except ValueError as e:
        raise KexError("bad ephemeral public key format") from e
    sign = resp[2 * ED25519_KEY_SIZE_BYTES:]

    k = key_agreement(eph_priv=eph_priv, eph_pub=q_s,
                      kdf=lambda x: HKDF(x, CHACHA20_KEY_SIZE_BYTES, b'', SHA512, num_keys=2))
    h = SHA512.new(
        k_s.export_key(format="raw") + q_c.export_key(format="raw") + q_s.export_key(format="raw") + k[0] + k[1])
    verifier = eddsa.new(k_s, "rfc8032")
    if not verifier.verify(h, sign):
        raise KexError("invalid hash signature")
    return k[0], k[1], k_s


def server_to_client(s: socket.socket, priv_key: ECC.EccKey):
    """
    Performs X25519 from host side
    :param s: TCP connection to client
    :param priv_key: Private key of the host
    :raises KexError: If ephemeral public key sent by the client is invalid
    """
    k_s = priv_key.public_key()
    buf = _recv_full(s, ED25519_KEY_SIZE_BYTES)
    try:
        q_c = _import_raw_ed25519_public_key(buf)
    except ValueError as e:
        raise KexError("bad ephemeral public key format") from e

    eph_priv = ECC.generate(curve="ed25519")
    q_s = eph_priv.public_key()
    k = key_agreement(eph_priv=eph_priv, eph_pub=q_s,
                      kdf=lambda x: HKDF(x, CHACHA20_KEY_SIZE_BYTES, b'', SHA512, num_keys=2))
    h = SHA512.new(
        k_s.export_key(format="raw") + q_c.export_key(format="raw") + q_s.export_key(format="raw") + k[0] + k[1])
    signer = eddsa.new(priv_key, "rfc8032")
    s.sendall(k_s.export_key(format="raw") + q_s.export_key(format="raw") + signer.sign(h))
