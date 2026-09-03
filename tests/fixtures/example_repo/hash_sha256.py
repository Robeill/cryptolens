import hashlib
import hmac
import secrets


def digest_sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def digest_sha512(payload):
    digest = hashlib.sha512()
    digest.update(payload)
    return digest.digest()


def digest_sha3(payload):
    return hashlib.sha3_256(payload).digest()


def legacy_md5_checksum(payload):
    return hashlib.md5(payload).hexdigest()


def legacy_sha1_fingerprint(payload):
    return hashlib.sha1(payload).hexdigest()


def by_name(payload):
    return hashlib.new("md5", payload).hexdigest()


def authenticate(key, message):
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def compare(left, right):
    return hmac.compare_digest(left, right)


def derive(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password, salt, 100000)


def session_id():
    return secrets.token_hex(32)
