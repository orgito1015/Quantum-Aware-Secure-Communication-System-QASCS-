from __future__ import annotations
import ssl
from pathlib import Path

CERT_DIR = Path(__file__).resolve().parent / "certs"
SERVER_CERT = CERT_DIR / "server.crt"
SERVER_KEY = CERT_DIR / "server.key"
CA_CERT = CERT_DIR / "ca.crt"

def make_server_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(SERVER_CERT), keyfile=str(SERVER_KEY))
    return ctx

def make_client_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=str(CA_CERT))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
