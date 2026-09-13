from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding


def new_signing_key():
    return ed25519.Ed25519PrivateKey.generate()


def sign_release(private_key, manifest):
    return private_key.sign(manifest)


def verify_release(public_key, signature, manifest):
    return public_key.verify(signature, manifest)


def sign_receipt(private_key, receipt):
    return private_key.sign(receipt, ec.ECDSA(hashes.SHA256()))


def sign_invoice(private_key, invoice):
    return private_key.sign(
        invoice,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def wrap_session_key(public_key, session_key):
    return public_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
