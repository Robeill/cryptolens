from __future__ import annotations

import re

_SQUASH = re.compile(r"[\s_.-]+")

_CANONICAL = {
    "md2": "MD2",
    "md4": "MD4",
    "md5": "MD5",
    "sha": "SHA-1",
    "sha1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha512224": "SHA-512/224",
    "sha512256": "SHA-512/256",
    "sha3224": "SHA3-224",
    "sha3256": "SHA3-256",
    "sha3384": "SHA3-384",
    "sha3512": "SHA3-512",
    "shake128": "SHAKE128",
    "shake256": "SHAKE256",
    "blake2b": "BLAKE2b",
    "blake2s": "BLAKE2s",
    "ripemd160": "RIPEMD-160",
    "aes": "AES",
    "aes128": "AES-128",
    "aes192": "AES-192",
    "aes256": "AES-256",
    "des": "DES",
    "3des": "3DES",
    "des3": "3DES",
    "tripledes": "3DES",
    "desede3": "3DES",
    "blowfish": "Blowfish",
    "camellia": "Camellia",
    "cast5": "CAST5",
    "idea": "IDEA",
    "seed": "SEED",
    "arc2": "RC2",
    "rc2": "RC2",
    "arc4": "RC4",
    "rc4": "RC4",
    "chacha20": "ChaCha20",
    "rsa": "RSA",
    "dsa": "DSA",
    "dh": "DH",
    "ecdh": "ECDH",
    "ecdsa": "ECDSA",
    "eddsa": "EdDSA",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
    "x25519": "X25519",
    "x448": "X448",
    "hmac": "HMAC",
    "pbkdf2": "PBKDF2",
    "hkdf": "HKDF",
    "scrypt": "scrypt",
    "argon2": "Argon2",
    "mlkem": "ML-KEM",
    "mldsa": "ML-DSA",
    "slhdsa": "SLH-DSA",
}


def normalize_algorithm(name: str | None) -> str:
    if not name:
        return "unknown"
    text = name.strip()
    if not text:
        return "unknown"
    squashed = _SQUASH.sub("", text).lower()
    if squashed in _CANONICAL:
        return _CANONICAL[squashed]
    if "-" in text:
        head, _, tail = text.partition("-")
        head_key = _SQUASH.sub("", head).lower()
        tail_key = _SQUASH.sub("", tail).lower()
        if head_key in _CANONICAL and tail_key in _CANONICAL:
            return f"{_CANONICAL[head_key]}-{_CANONICAL[tail_key]}"
    return text


def normalize_composite(*parts: str | None) -> str:
    return "-".join(normalize_algorithm(p) for p in parts if p)
