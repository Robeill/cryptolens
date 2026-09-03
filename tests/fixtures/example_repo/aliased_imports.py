import hashlib as hl
import hmac as message_auth
from hashlib import sha256 as digest_function

import cryptography.hazmat.primitives.hashes
from cryptography.hazmat.primitives.asymmetric import ec as elliptic


def aliased_module(payload):
    return hl.sha256(payload).hexdigest()


def aliased_member(payload):
    return digest_function(payload).hexdigest()


def aliased_hmac(key, payload):
    return message_auth.new(key, payload, hl.sha256).digest()


def deep_dotted_import():
    return cryptography.hazmat.primitives.hashes.SHA256()


def aliased_curve():
    return elliptic.generate_private_key(elliptic.SECP256R1())
