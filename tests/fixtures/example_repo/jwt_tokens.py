import jwt


def issue_hs256(payload, secret):
    return jwt.encode(payload, secret, algorithm="HS256")


def issue_rs256(payload, private_key):
    return jwt.encode(payload, private_key, algorithm="RS256")


def issue_ps512(payload, private_key):
    return jwt.encode(payload, private_key, algorithm="PS512")


def issue_es256(payload, private_key):
    return jwt.encode(payload, private_key, algorithm="ES256")


def issue_eddsa(payload, private_key):
    return jwt.encode(payload, private_key, algorithm="EdDSA")


def issue_unsigned(payload):
    return jwt.encode(payload, None, algorithm="none")


def issue_with_chosen_algorithm(payload, secret, chosen):
    return jwt.encode(payload, secret, algorithm=chosen)


def read_verified(token, public_key):
    return jwt.decode(token, public_key, algorithms=["RS256"])


def read_several_accepted(token, key):
    return jwt.decode(token, key, algorithms=["HS256", "RS256"])


def read_accepting_none(token, key):
    return jwt.decode(token, key, algorithms=["HS256", "none"])


def read_legacy_unverified(token):
    return jwt.decode(token, verify=False)


def read_unverified_options(token):
    return jwt.decode(token, options={"verify_signature": False})
