import base64
import json
import zlib


def encrypt_payload(payload):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(zlib.compress(raw)).decode()


def decrypt_payload(encoded):
    raw = zlib.decompress(base64.urlsafe_b64decode(encoded))
    return json.loads(raw)


def encode_basic_auth(username, password):
    return base64.b64encode(f"{username}:{password}".encode()).decode()
