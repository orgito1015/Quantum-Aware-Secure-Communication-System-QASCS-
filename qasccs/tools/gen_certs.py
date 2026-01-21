from __future__ import annotations
import argparse
from pathlib import Path
import datetime
from datetime import UTC
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def _write(p: Path, data: bytes):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)

def main():
    ap = argparse.ArgumentParser(description="Generate dev-only CA + server certs for QASCS")
    ap.add_argument("--out", required=True, help="Output directory")
    args = ap.parse_args()
    out = Path(args.out)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QASCS-Dev"),
        x509.NameAttribute(NameOID.COMMON_NAME, "QASCS Dev CA"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(UTC) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QASCS-Dev"),
        x509.NameAttribute(NameOID.COMMON_NAME, "qasccs.local"),
    ])

    san = x509.SubjectAlternativeName([
        x509.DNSName("qasccs.local"),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ])

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(UTC) + datetime.timedelta(days=825))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    _write(out / "ca.crt", ca_cert.public_bytes(serialization.Encoding.PEM))
    _write(out / "ca.key", ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    _write(out / "server.crt", server_cert.public_bytes(serialization.Encoding.PEM))
    _write(out / "server.key", server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

    print(f"[gen_certs] Wrote dev certs to: {out.resolve()}")
    print("[gen_certs] WARNING: dev-only self-signed CA. Do not use in production.")

if __name__ == "__main__":
    main()
