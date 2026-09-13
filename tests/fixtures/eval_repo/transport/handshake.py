from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def curve25519_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def curve25519_shared_secret(private_key, peer_public_key):
    return private_key.exchange(peer_public_key)


def nist_keypair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    return private_key, private_key.public_key()


def nist_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)


def derive_session_key(shared_secret, info):
    kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return kdf.derive(shared_secret)
