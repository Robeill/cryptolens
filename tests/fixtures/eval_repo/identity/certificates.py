from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def new_service_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def new_legacy_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def load_certificate(pem_bytes):
    return x509.load_pem_x509_certificate(pem_bytes)


def load_key(pem_bytes, password):
    return serialization.load_pem_private_key(pem_bytes, password=password)


def export_public_key(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
