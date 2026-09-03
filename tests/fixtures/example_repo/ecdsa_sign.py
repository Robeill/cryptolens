from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


def make_p256_key():
    return ec.generate_private_key(ec.SECP256R1())


def make_p384_key():
    return ec.generate_private_key(ec.SECP384R1())


def sign_ecdsa(private_key, message):
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def verify_ecdsa(public_key, signature, message):
    return public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))


def make_ed25519_key():
    return ed25519.Ed25519PrivateKey.generate()


def sign_ed25519(private_key, message):
    return private_key.sign(message)


def exchange_ecdh(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)
