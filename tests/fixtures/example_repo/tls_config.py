import socket
import ssl


def secure_context(cafile):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ECDHE+AESGCM")
    return context


def insecure_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def connect(host, port, context):
    raw = socket.create_connection((host, port))
    return context.wrap_socket(raw, server_hostname=host)


def unverified_context():
    return ssl._create_unverified_context()
