import datetime

import jwt


def issue_session_token(user_id, secret):
    payload = {
        "sub": user_id,
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def read_session_token(token, secret):
    return jwt.decode(token, secret, algorithms=["HS256"])


def issue_service_token(claims, private_key):
    return jwt.encode(claims, private_key, algorithm="RS256")


def read_service_token(token, public_key):
    return jwt.decode(token, public_key, algorithms=["RS256"])


def read_untrusted(token):
    return jwt.decode(token, options={"verify_signature": False})
