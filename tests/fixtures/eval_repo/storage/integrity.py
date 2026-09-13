import hashlib
import hmac

CHUNK = 65536


def file_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def sign_manifest(key, manifest):
    return hmac.new(key, manifest, hashlib.sha256).hexdigest()


def check_manifest(key, manifest, expected):
    actual = hmac.new(key, manifest, hashlib.sha256).hexdigest()
    return hmac.compare_digest(actual, expected)


def strong_digest(payload):
    return hashlib.sha512(payload).hexdigest()
