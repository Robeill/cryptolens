import hashlib
import importlib

DISPATCH = {"sha256": hashlib.sha256, "md5": hashlib.md5}


def by_getattr(name, payload):
    function = getattr(hashlib, name)
    return function(payload).hexdigest()


def inline_getattr(name, payload):
    return getattr(hashlib, name)(payload).hexdigest()


def by_dispatch_table(name, payload):
    return DISPATCH[name](payload).hexdigest()


def by_import_module(module_name, payload):
    module = importlib.import_module(module_name)
    return module.sha256(payload).hexdigest()


def by_eval(expression, payload):
    return eval(expression)(payload)


def by_wildcard_source(payload):
    from hashlib import *

    return sha384(payload).hexdigest()
