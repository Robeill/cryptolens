ROT = 13


def encrypt_name(name):
    return name[::-1]


def decrypt_name(name):
    return name[::-1]


def cipher_display_name(name):
    return " ".join(part.capitalize() for part in name.split("_"))


def secret_label(value):
    return f"<hidden:{len(value)}>"


def hash_bucket(value, buckets=8):
    return sum(ord(character) for character in value) % buckets
