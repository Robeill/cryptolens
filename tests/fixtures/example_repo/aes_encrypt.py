import os

from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_gcm(key, plaintext):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    return iv, encryptor.update(plaintext) + encryptor.finalize(), encryptor.tag


def decrypt_gcm(key, iv, ciphertext, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def encrypt_cbc(key, plaintext):
    iv = os.urandom(16)
    padder = symmetric_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return iv, encryptor.update(padded) + encryptor.finalize()


def encrypt_ecb_insecure(key, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def encrypt_legacy_3des(key, iv, plaintext):
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()
