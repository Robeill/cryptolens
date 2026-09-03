from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptolens.model import (
    AssetType,
    CryptoFunction,
    CryptoMode,
    CryptoPadding,
    CryptoPrimitive,
    CryptoPurpose,
    CryptoStatus,
)

UNSET = object()

PYCA = "cryptography.hazmat.primitives"
PYCA_ASYM = f"{PYCA}.asymmetric"
PYCA_CIPHERS = f"{PYCA}.ciphers"


@dataclass(frozen=True)
class Rule:
    match: str
    algorithm: str
    primitive: CryptoPrimitive
    purpose: CryptoPurpose = CryptoPurpose.UNKNOWN
    functions: tuple[CryptoFunction, ...] = ()
    status: CryptoStatus = CryptoStatus.CLASSICAL
    asset_type: AssetType = AssetType.ALGORITHM
    mode: CryptoMode = CryptoMode.UNKNOWN
    padding: CryptoPadding = CryptoPadding.UNKNOWN
    key_size: int | None = None
    parameter_set: str | None = None
    key_size_kwarg: str | None = None
    key_size_arg: int | None = None
    classical_security_level: int | None = None
    algorithm_arg: int | None = None
    mode_arg: int | None = None
    curve_arg: int | None = None
    digest_arg: int | None = None
    digest_kwarg: str | None = None
    name_arg: int | None = None
    value_name: str | None = None
    value_equals: Any = UNSET
    consumes_args: bool = False
    emits: bool = True
    confidence: float | None = None
    detector: str = ""


CIPHER_ALGORITHMS: dict[str, tuple[str, CryptoPrimitive, int | None]] = {
    f"{PYCA_CIPHERS}.algorithms.AES": ("AES", CryptoPrimitive.BLOCK_CIPHER, None),
    f"{PYCA_CIPHERS}.algorithms.AES128": ("AES-128", CryptoPrimitive.BLOCK_CIPHER, 128),
    f"{PYCA_CIPHERS}.algorithms.AES256": ("AES-256", CryptoPrimitive.BLOCK_CIPHER, 256),
    f"{PYCA_CIPHERS}.algorithms.Camellia": ("Camellia", CryptoPrimitive.BLOCK_CIPHER, None),
    f"{PYCA_CIPHERS}.algorithms.TripleDES": ("3DES", CryptoPrimitive.BLOCK_CIPHER, 112),
    f"{PYCA_CIPHERS}.algorithms.Blowfish": ("Blowfish", CryptoPrimitive.BLOCK_CIPHER, None),
    f"{PYCA_CIPHERS}.algorithms.CAST5": ("CAST5", CryptoPrimitive.BLOCK_CIPHER, None),
    f"{PYCA_CIPHERS}.algorithms.IDEA": ("IDEA", CryptoPrimitive.BLOCK_CIPHER, None),
    f"{PYCA_CIPHERS}.algorithms.SEED": ("SEED", CryptoPrimitive.BLOCK_CIPHER, 128),
    f"{PYCA_CIPHERS}.algorithms.ARC4": ("RC4", CryptoPrimitive.STREAM_CIPHER, None),
    f"{PYCA_CIPHERS}.algorithms.ChaCha20": ("ChaCha20", CryptoPrimitive.STREAM_CIPHER, 256),
}

CIPHER_MODES: dict[str, CryptoMode] = {
    f"{PYCA_CIPHERS}.modes.CBC": CryptoMode.CBC,
    f"{PYCA_CIPHERS}.modes.CCM": CryptoMode.CCM,
    f"{PYCA_CIPHERS}.modes.CFB": CryptoMode.CFB,
    f"{PYCA_CIPHERS}.modes.CFB8": CryptoMode.CFB,
    f"{PYCA_CIPHERS}.modes.CTR": CryptoMode.CTR,
    f"{PYCA_CIPHERS}.modes.ECB": CryptoMode.ECB,
    f"{PYCA_CIPHERS}.modes.GCM": CryptoMode.GCM,
    f"{PYCA_CIPHERS}.modes.OFB": CryptoMode.OFB,
    f"{PYCA_CIPHERS}.modes.XTS": CryptoMode.OTHER,
}

CURVES: dict[str, tuple[str, int]] = {
    f"{PYCA_ASYM}.ec.SECP192R1": ("SECP192R1", 96),
    f"{PYCA_ASYM}.ec.SECP224R1": ("SECP224R1", 112),
    f"{PYCA_ASYM}.ec.SECP256K1": ("SECP256K1", 128),
    f"{PYCA_ASYM}.ec.SECP256R1": ("SECP256R1", 128),
    f"{PYCA_ASYM}.ec.SECP384R1": ("SECP384R1", 192),
    f"{PYCA_ASYM}.ec.SECP521R1": ("SECP521R1", 256),
    f"{PYCA_ASYM}.ec.BrainpoolP256R1": ("brainpoolP256r1", 128),
    f"{PYCA_ASYM}.ec.BrainpoolP384R1": ("brainpoolP384r1", 192),
}

HASH_STRENGTH: dict[str, int | None] = {
    "MD5": None,
    "SHA-1": None,
    "SHA-224": 112,
    "SHA-256": 128,
    "SHA-384": 192,
    "SHA-512": 256,
    "SHA3-256": 128,
    "SHA3-384": 192,
    "SHA3-512": 256,
    "BLAKE2b": 256,
    "BLAKE2s": 128,
}

_HASHLIB = (
    ("md5", "MD5", None),
    ("sha1", "SHA-1", None),
    ("sha224", "SHA-224", 112),
    ("sha256", "SHA-256", 128),
    ("sha384", "SHA-384", 192),
    ("sha512", "SHA-512", 256),
    ("sha3_224", "SHA3-224", 112),
    ("sha3_256", "SHA3-256", 128),
    ("sha3_384", "SHA3-384", 192),
    ("sha3_512", "SHA3-512", 256),
    ("blake2b", "BLAKE2b", 256),
    ("blake2s", "BLAKE2s", 128),
)

_PYCA_HASHES = (
    ("MD5", "MD5", None),
    ("SHA1", "SHA-1", None),
    ("SHA224", "SHA-224", 112),
    ("SHA256", "SHA-256", 128),
    ("SHA384", "SHA-384", 192),
    ("SHA512", "SHA-512", 256),
    ("SHA3_256", "SHA3-256", 128),
    ("SHA3_512", "SHA3-512", 256),
    ("BLAKE2b", "BLAKE2b", 256),
    ("BLAKE2s", "BLAKE2s", 128),
)


def _hash_rules() -> list[Rule]:
    rules = [
        Rule(
            match=f"hashlib.{attribute}",
            algorithm=algorithm,
            primitive=CryptoPrimitive.HASH,
            purpose=CryptoPurpose.HASHING,
            functions=(CryptoFunction.DIGEST,),
            classical_security_level=strength,
            detector=f"hashlib.{attribute}",
        )
        for attribute, algorithm, strength in _HASHLIB
    ]
    rules += [
        Rule(
            match=f"{PYCA}.hashes.{attribute}",
            algorithm=algorithm,
            primitive=CryptoPrimitive.HASH,
            purpose=CryptoPurpose.HASHING,
            functions=(CryptoFunction.DIGEST,),
            classical_security_level=strength,
            detector=f"pyca.hashes.{attribute}",
        )
        for attribute, algorithm, strength in _PYCA_HASHES
    ]
    return rules


def _cipher_rules() -> list[Rule]:
    rules = [
        Rule(
            match=f"{PYCA_CIPHERS}.Cipher",
            algorithm="unknown",
            primitive=CryptoPrimitive.BLOCK_CIPHER,
            purpose=CryptoPurpose.ENCRYPTION,
            functions=(CryptoFunction.ENCRYPT, CryptoFunction.DECRYPT),
            algorithm_arg=0,
            mode_arg=1,
            consumes_args=True,
            detector="pyca.cipher",
        )
    ]
    rules += [
        Rule(
            match=name,
            algorithm=algorithm,
            primitive=primitive,
            purpose=CryptoPurpose.ENCRYPTION,
            functions=(CryptoFunction.ENCRYPT,),
            classical_security_level=strength,
            detector="pyca.cipher.algorithm",
        )
        for name, (algorithm, primitive, strength) in CIPHER_ALGORITHMS.items()
    ]
    return rules


RULES: tuple[Rule, ...] = tuple(
    _hash_rules()
    + _cipher_rules()
    + [
        Rule(
            match="hashlib.new",
            algorithm="unknown",
            primitive=CryptoPrimitive.HASH,
            purpose=CryptoPurpose.HASHING,
            functions=(CryptoFunction.DIGEST,),
            name_arg=0,
            consumes_args=True,
            detector="hashlib.new",
        ),
        Rule(
            match="hmac.new",
            algorithm="HMAC",
            primitive=CryptoPrimitive.MAC,
            purpose=CryptoPurpose.MAC,
            functions=(CryptoFunction.TAG,),
            digest_arg=2,
            digest_kwarg="digestmod",
            consumes_args=True,
            detector="hmac.new",
        ),
        Rule(
            match=f"{PYCA}.hmac.HMAC",
            algorithm="HMAC",
            primitive=CryptoPrimitive.MAC,
            purpose=CryptoPurpose.MAC,
            functions=(CryptoFunction.TAG,),
            digest_arg=1,
            consumes_args=True,
            detector="pyca.hmac",
        ),
        Rule(
            match="hashlib.pbkdf2_hmac",
            algorithm="PBKDF2",
            primitive=CryptoPrimitive.KDF,
            purpose=CryptoPurpose.KEY_DERIVATION,
            functions=(CryptoFunction.KEYDERIVE,),
            digest_arg=0,
            consumes_args=True,
            detector="hashlib.pbkdf2",
        ),
        Rule(
            match="hashlib.scrypt",
            algorithm="scrypt",
            primitive=CryptoPrimitive.KDF,
            purpose=CryptoPurpose.KEY_DERIVATION,
            functions=(CryptoFunction.KEYDERIVE,),
            detector="hashlib.scrypt",
        ),
        Rule(
            match=f"{PYCA}.kdf.pbkdf2.PBKDF2HMAC",
            algorithm="PBKDF2",
            primitive=CryptoPrimitive.KDF,
            purpose=CryptoPurpose.KEY_DERIVATION,
            functions=(CryptoFunction.KEYDERIVE,),
            consumes_args=True,
            detector="pyca.pbkdf2",
        ),
        Rule(
            match=f"{PYCA}.kdf.hkdf.HKDF",
            algorithm="HKDF",
            primitive=CryptoPrimitive.KDF,
            purpose=CryptoPurpose.KEY_DERIVATION,
            functions=(CryptoFunction.KEYDERIVE,),
            consumes_args=True,
            detector="pyca.hkdf",
        ),
        Rule(
            match=f"{PYCA_ASYM}.rsa.generate_private_key",
            algorithm="RSA",
            primitive=CryptoPrimitive.PKE,
            functions=(CryptoFunction.KEYGEN,),
            key_size_kwarg="key_size",
            key_size_arg=1,
            detector="pyca.rsa.keygen",
        ),
        Rule(
            match=f"{PYCA_ASYM}.rsa.generate_private_key.sign",
            algorithm="RSA",
            primitive=CryptoPrimitive.SIGNATURE,
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
            functions=(CryptoFunction.SIGN,),
            consumes_args=True,
            detector="pyca.rsa.sign",
        ),
        Rule(
            match=f"{PYCA_ASYM}.padding.MGF1",
            algorithm="MGF1",
            primitive=CryptoPrimitive.OTHER,
            consumes_args=True,
            emits=False,
            detector="pyca.rsa.mgf1",
        ),
        Rule(
            match=f"{PYCA_ASYM}.padding.PSS",
            algorithm="RSA",
            primitive=CryptoPrimitive.SIGNATURE,
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
            functions=(CryptoFunction.SIGN,),
            padding=CryptoPadding.OTHER,
            consumes_args=True,
            detector="pyca.rsa.pss",
        ),
        Rule(
            match=f"{PYCA_ASYM}.padding.OAEP",
            algorithm="RSA",
            primitive=CryptoPrimitive.PKE,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            functions=(CryptoFunction.ENCRYPT,),
            padding=CryptoPadding.OAEP,
            consumes_args=True,
            detector="pyca.rsa.oaep",
        ),
        Rule(
            match=f"{PYCA_ASYM}.padding.PKCS1v15",
            algorithm="RSA",
            primitive=CryptoPrimitive.PKE,
            padding=CryptoPadding.PKCS1V15,
            detector="pyca.rsa.pkcs1v15",
        ),
        Rule(
            match=f"{PYCA}.padding.PKCS7",
            algorithm="PKCS7",
            primitive=CryptoPrimitive.OTHER,
            purpose=CryptoPurpose.ENCRYPTION,
            padding=CryptoPadding.PKCS7,
            detector="pyca.padding.pkcs7",
        ),
        Rule(
            match=f"{PYCA_ASYM}.ec.generate_private_key",
            algorithm="EC",
            primitive=CryptoPrimitive.UNKNOWN,
            functions=(CryptoFunction.KEYGEN,),
            curve_arg=0,
            consumes_args=True,
            detector="pyca.ec.keygen",
        ),
        Rule(
            match=f"{PYCA_ASYM}.ec.ECDSA",
            algorithm="ECDSA",
            primitive=CryptoPrimitive.SIGNATURE,
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
            functions=(CryptoFunction.SIGN,),
            consumes_args=True,
            detector="pyca.ecdsa",
        ),
        Rule(
            match=f"{PYCA_ASYM}.ec.ECDH",
            algorithm="ECDH",
            primitive=CryptoPrimitive.KEY_AGREE,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            functions=(CryptoFunction.ENCAPSULATE,),
            detector="pyca.ecdh",
        ),
        Rule(
            match=f"{PYCA_ASYM}.ed25519.Ed25519PrivateKey.generate",
            algorithm="Ed25519",
            primitive=CryptoPrimitive.SIGNATURE,
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
            functions=(CryptoFunction.KEYGEN, CryptoFunction.SIGN),
            parameter_set="Ed25519",
            classical_security_level=128,
            detector="pyca.ed25519",
        ),
        Rule(
            match=f"{PYCA_ASYM}.ed448.Ed448PrivateKey.generate",
            algorithm="Ed448",
            primitive=CryptoPrimitive.SIGNATURE,
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
            functions=(CryptoFunction.KEYGEN, CryptoFunction.SIGN),
            parameter_set="Ed448",
            classical_security_level=224,
            detector="pyca.ed448",
        ),
        Rule(
            match=f"{PYCA_ASYM}.x25519.X25519PrivateKey.generate",
            algorithm="X25519",
            primitive=CryptoPrimitive.KEY_AGREE,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            functions=(CryptoFunction.KEYGEN,),
            parameter_set="X25519",
            classical_security_level=128,
            detector="pyca.x25519",
        ),
        Rule(
            match=f"{PYCA_ASYM}.dh.generate_parameters",
            algorithm="DH",
            primitive=CryptoPrimitive.KEY_AGREE,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            functions=(CryptoFunction.KEYGEN,),
            key_size_kwarg="key_size",
            detector="pyca.dh",
        ),
        Rule(
            match=f"{PYCA_ASYM}.dsa.generate_private_key",
            algorithm="DSA",
            primitive=CryptoPrimitive.SIGNATURE,
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
            functions=(CryptoFunction.KEYGEN,),
            key_size_kwarg="key_size",
            key_size_arg=0,
            detector="pyca.dsa",
        ),
        Rule(
            match=f"{PYCA}.serialization.load_pem_private_key",
            algorithm="unknown",
            primitive=CryptoPrimitive.UNKNOWN,
            asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
            functions=(CryptoFunction.OTHER,),
            detector="pyca.load_private_key",
        ),
        Rule(
            match="secrets.token_bytes",
            algorithm="CSPRNG",
            primitive=CryptoPrimitive.DRBG,
            purpose=CryptoPurpose.RANDOM,
            functions=(CryptoFunction.GENERATE,),
            detector="secrets.token_bytes",
        ),
        Rule(
            match="secrets.token_hex",
            algorithm="CSPRNG",
            primitive=CryptoPrimitive.DRBG,
            purpose=CryptoPurpose.RANDOM,
            functions=(CryptoFunction.GENERATE,),
            detector="secrets.token_hex",
        ),
        Rule(
            match="secrets.token_urlsafe",
            algorithm="CSPRNG",
            primitive=CryptoPrimitive.DRBG,
            purpose=CryptoPurpose.RANDOM,
            functions=(CryptoFunction.GENERATE,),
            detector="secrets.token_urlsafe",
        ),
        Rule(
            match="os.urandom",
            algorithm="CSPRNG",
            primitive=CryptoPrimitive.DRBG,
            purpose=CryptoPurpose.RANDOM,
            functions=(CryptoFunction.GENERATE,),
            detector="os.urandom",
        ),
        Rule(
            match="random.random",
            algorithm="Mersenne Twister",
            primitive=CryptoPrimitive.DRBG,
            purpose=CryptoPurpose.RANDOM,
            functions=(CryptoFunction.GENERATE,),
            detector="random.insecure",
        ),
        Rule(
            match="random.randint",
            algorithm="Mersenne Twister",
            primitive=CryptoPrimitive.DRBG,
            purpose=CryptoPurpose.RANDOM,
            functions=(CryptoFunction.GENERATE,),
            detector="random.insecure",
        ),
        Rule(
            match="getattr",
            algorithm="unknown",
            primitive=CryptoPrimitive.UNKNOWN,
            value_name="hashlib",
            confidence=0.3,
            detector="dynamic.getattr.hashlib",
        ),
        Rule(
            match="ssl.create_default_context",
            algorithm="TLS",
            primitive=CryptoPrimitive.OTHER,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            asset_type=AssetType.PROTOCOL,
            detector="ssl.default_context",
        ),
        Rule(
            match="ssl.SSLContext",
            algorithm="TLS",
            primitive=CryptoPrimitive.OTHER,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            asset_type=AssetType.PROTOCOL,
            detector="ssl.context",
        ),
        Rule(
            match="ssl._create_unverified_context",
            algorithm="TLS",
            primitive=CryptoPrimitive.OTHER,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            asset_type=AssetType.PROTOCOL,
            detector="ssl.unverified_context",
        ),
        Rule(
            match="<assign>.verify_mode",
            algorithm="TLS",
            primitive=CryptoPrimitive.OTHER,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            asset_type=AssetType.PROTOCOL,
            value_name="ssl.CERT_NONE",
            detector="ssl.verification_disabled",
        ),
        Rule(
            match="<assign>.check_hostname",
            algorithm="TLS",
            primitive=CryptoPrimitive.OTHER,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            asset_type=AssetType.PROTOCOL,
            value_equals=False,
            detector="ssl.hostname_check_disabled",
        ),
    ]
)
