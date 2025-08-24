import base64
from asyncio import StreamReader, StreamWriter

from Crypto.Hash import SHA512
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from Crypto.Signature import eddsa

from protocol import util, CHACHA20_KEY_SIZE_BYTES, ED25519_KEY_SIZE_BYTES, ED25519_EDDSA_SIZE_BYTES


class KexError(Exception):
    pass


async def client_to_server(rw: tuple[StreamReader, StreamWriter], host_public_key: EccKey | None):
    """
    Performs X25519 from client side
    :param rw: Tuple of asyncio StreamReader and StreamWriter.
    :param host_public_key: Public key of remote host
    :returns: (k_1, k_2, host_pub_key), where derived_key is a tuple of 2 256 bits byte string.
    :raises KexError: If signature is invalid or public keys sent by remote host is invalid
    """
    r, w = rw

    eph_priv = ECC.generate(curve="ed25519")
    q_c = eph_priv.public_key()
    w.write(q_c.export_key(format="raw"))
    await w.drain()

    # K_S, Q_S, signature on hash
    resp = await r.readexactly(2 * ED25519_KEY_SIZE_BYTES + ED25519_EDDSA_SIZE_BYTES)
    try:
        k_s = util.import_raw_ed25519_public_key(resp[:ED25519_KEY_SIZE_BYTES])
    except ValueError as e:
        raise KexError("bad host public key format") from e
    if host_public_key is not None and host_public_key.export_key(format="raw") != resp[:ED25519_KEY_SIZE_BYTES]:
        e = KexError("incorrect host public key")
        e.add_note(f"received raw host key is: {base64.b64encode(resp[:ED25519_KEY_SIZE_BYTES])}")
        raise e

    try:
        q_s = util.import_raw_ed25519_public_key(resp[ED25519_KEY_SIZE_BYTES:2 * ED25519_KEY_SIZE_BYTES])
    except ValueError as e:
        raise KexError("bad ephemeral public key format") from e
    sign = resp[2 * ED25519_KEY_SIZE_BYTES:]

    k = key_agreement(eph_priv=eph_priv, eph_pub=q_s,
                      kdf=lambda x: HKDF(x, CHACHA20_KEY_SIZE_BYTES, b'', SHA512, num_keys=2))
    h = SHA512.new(
        k_s.export_key(format="raw") + q_c.export_key(format="raw") + q_s.export_key(format="raw") + k[0] + k[1])
    verifier = eddsa.new(k_s, "rfc8032")
    verifier.verify(h, sign)
    return k[0], k[1], k_s


async def server_to_client(rw: tuple[StreamReader, StreamWriter], priv_key: ECC.EccKey):
    """
    Performs X25519 from host side
    :param rw: Tuple of asyncio StreamReader and StreamWriter.
    :param priv_key: Private key of the host
    :returns: k_1, k_2
    :raises KexError: If ephemeral public key sent by the client is invalid
    """
    r, w = rw

    k_s = priv_key.public_key()
    buf = await r.readexactly(ED25519_KEY_SIZE_BYTES)
    try:
        q_c = util.import_raw_ed25519_public_key(buf)
    except ValueError as e:
        raise KexError("bad ephemeral public key format") from e

    eph_priv = ECC.generate(curve="ed25519")
    q_s = eph_priv.public_key()
    k = key_agreement(eph_priv=eph_priv, eph_pub=q_c,
                      kdf=lambda x: HKDF(x, CHACHA20_KEY_SIZE_BYTES, b'', SHA512, num_keys=2))
    h = SHA512.new(
        k_s.export_key(format="raw") + q_c.export_key(format="raw") + q_s.export_key(format="raw") + k[0] + k[1])
    signer = eddsa.new(priv_key, "rfc8032")
    w.write(k_s.export_key(format="raw") + q_s.export_key(format="raw") + signer.sign(h))
    await w.drain()

    return k[0], k[1]
