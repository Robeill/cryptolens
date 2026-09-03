import hashlib
from hashlib import md5, sha256

try:
    from fast_hashes import sha256 as accelerated_sha256
except ImportError:
    from hashlib import sha256 as accelerated_sha256


def indirect_reference(payload):
    algorithm = hashlib.sha256
    return algorithm(payload).hexdigest()


def reassigned_reference(payload, legacy):
    algorithm = sha256
    if legacy:
        algorithm = md5
    return algorithm(payload).hexdigest()


def conditional_backend(payload):
    return accelerated_sha256(payload).hexdigest()


def scoped_import(payload):
    import hashlib as scoped

    return scoped.sha512(payload).hexdigest()


class Hasher:
    def __init__(self):
        self.algorithm = hashlib.sha256
        self.signing_key = None

    def digest(self, payload):
        return self.algorithm(payload).hexdigest()


def shadowed(payload):
    hashlib = load_backend()
    return hashlib.sha256(payload)


def load_backend():
    return None
