import hashlib


def etag_for(body):
    return hashlib.md5(body).hexdigest()


def cache_key(namespace, *parts):
    joined = ":".join(str(part) for part in parts)
    return f"{namespace}:{hashlib.md5(joined.encode()).hexdigest()}"


def bucket_for(user_id, buckets=16):
    return int(hashlib.md5(str(user_id).encode()).hexdigest(), 16) % buckets
