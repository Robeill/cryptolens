import secrets

SESSION_BYTES = 32


def new_session_id():
    return secrets.token_hex(SESSION_BYTES)


def new_csrf_token():
    return secrets.token_urlsafe(SESSION_BYTES)


def new_api_key():
    return secrets.token_bytes(SESSION_BYTES)


def constant_time_match(left, right):
    return secrets.compare_digest(left, right)
