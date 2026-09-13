import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def legacy_fingerprint(payload):
    return hashlib.md5(payload).hexdigest()


def legacy_signature(payload, secret):
    return hashlib.md5(secret + payload).hexdigest()


def decrypt_archive(key, iv, ciphertext):
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def decrypt_export(key, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def decrypt_stream(key, ciphertext):
    cipher = Cipher(algorithms.ARC4(key), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)
