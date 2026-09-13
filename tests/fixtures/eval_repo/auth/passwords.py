import hashlib
import os
import secrets


def make_salt():
    return os.urandom(16)


def hash_password(password, salt, iterations=600000):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)


def hash_password_scrypt(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)


def verify_password(password, salt, expected, iterations=600000):
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return secrets.compare_digest(candidate, expected)


def legacy_hash(password):
    return hashlib.sha1(password.encode()).hexdigest()
