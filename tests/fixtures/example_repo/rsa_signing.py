from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def make_strong_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_weak_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def sign_pss(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


def sign_pkcs1(private_key, message):
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def verify(public_key, signature, message):
    return public_key.verify(
        signature,
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


def encrypt_key_material(public_key, secret):
    return public_key.encrypt(
        secret,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def load_key(pem_bytes, password):
    return serialization.load_pem_private_key(pem_bytes, password=password)
