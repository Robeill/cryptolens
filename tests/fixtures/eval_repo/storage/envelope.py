import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def new_fernet_key():
    return Fernet.generate_key()


def seal(token_key, plaintext):
    return Fernet(token_key).encrypt(plaintext)


def unseal(token_key, ciphertext):
    return Fernet(token_key).decrypt(ciphertext)


def new_aead_key():
    return AESGCM.generate_key(bit_length=256)


def encrypt_blob(key, plaintext, associated_data):
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, associated_data)


def decrypt_blob(key, nonce, ciphertext, associated_data):
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
