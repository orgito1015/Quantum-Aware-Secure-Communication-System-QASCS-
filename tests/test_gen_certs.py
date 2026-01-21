import pytest
import tempfile
import shutil
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from qasccs.tools.gen_certs import main
import sys
from unittest.mock import patch


@pytest.fixture
def temp_cert_dir():
    """Create a temporary directory for certificate generation"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


def test_gen_certs_creates_all_files(temp_cert_dir):
    """Test that gen_certs creates all required certificate files"""
    test_args = ["prog", "--out", temp_cert_dir]
    
    with patch.object(sys, 'argv', test_args):
        main()
    
    cert_dir = Path(temp_cert_dir)
    
    # Check all files exist
    assert (cert_dir / "ca.crt").exists()
    assert (cert_dir / "ca.key").exists()
    assert (cert_dir / "server.crt").exists()
    assert (cert_dir / "server.key").exists()


def test_gen_certs_ca_is_valid(temp_cert_dir):
    """Test that generated CA certificate is valid"""
    test_args = ["prog", "--out", temp_cert_dir]
    
    with patch.object(sys, 'argv', test_args):
        main()
    
    cert_file = Path(temp_cert_dir) / "ca.crt"
    cert_data = cert_file.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)
    
    # Check basic certificate properties
    assert cert.subject == cert.issuer  # Self-signed
    assert cert.version == x509.Version.v3
    
    # Check CA extension
    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic_constraints.value.ca is True


def test_gen_certs_server_cert_is_valid(temp_cert_dir):
    """Test that generated server certificate is valid"""
    test_args = ["prog", "--out", temp_cert_dir]
    
    with patch.object(sys, 'argv', test_args):
        main()
    
    cert_file = Path(temp_cert_dir) / "server.crt"
    cert_data = cert_file.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)
    
    # Check basic certificate properties
    assert cert.version == x509.Version.v3
    
    # Check NOT a CA
    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic_constraints.value.ca is False
    
    # Check SAN extension
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san is not None
    
    # Check for expected SANs
    dns_names = san.value.get_values_for_type(x509.DNSName)
    assert "localhost" in dns_names
    assert "qasccs.local" in dns_names


def test_gen_certs_ca_key_is_valid(temp_cert_dir):
    """Test that generated CA private key is valid"""
    test_args = ["prog", "--out", temp_cert_dir]
    
    with patch.object(sys, 'argv', test_args):
        main()
    
    key_file = Path(temp_cert_dir) / "ca.key"
    key_data = key_file.read_bytes()
    
    # Should not raise exception if valid
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = serialization.load_pem_private_key(key_data, password=None)
    
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048


def test_gen_certs_server_key_is_valid(temp_cert_dir):
    """Test that generated server private key is valid"""
    test_args = ["prog", "--out", temp_cert_dir]
    
    with patch.object(sys, 'argv', test_args):
        main()
    
    key_file = Path(temp_cert_dir) / "server.key"
    key_data = key_file.read_bytes()
    
    # Should not raise exception if valid
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = serialization.load_pem_private_key(key_data, password=None)
    
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048


def test_gen_certs_creates_directory_if_not_exists(temp_cert_dir):
    """Test that gen_certs creates the output directory if it doesn't exist"""
    nested_dir = Path(temp_cert_dir) / "nested" / "certs"
    test_args = ["prog", "--out", str(nested_dir)]
    
    with patch.object(sys, 'argv', test_args):
        main()
    
    assert nested_dir.exists()
    assert (nested_dir / "ca.crt").exists()


def test_gen_certs_server_signed_by_ca(temp_cert_dir):
    """Test that server certificate is signed by CA"""
    test_args = ["prog", "--out", temp_cert_dir]
    
    with patch.object(sys, 'argv', test_args):
        main()
    
    # Load CA cert
    ca_cert_data = (Path(temp_cert_dir) / "ca.crt").read_bytes()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_data)
    
    # Load server cert
    server_cert_data = (Path(temp_cert_dir) / "server.crt").read_bytes()
    server_cert = x509.load_pem_x509_certificate(server_cert_data)
    
    # Server cert issuer should match CA subject
    assert server_cert.issuer == ca_cert.subject


def test_gen_certs_validity_periods(temp_cert_dir):
    """Test that certificates have reasonable validity periods"""
    test_args = ["prog", "--out", temp_cert_dir]
    
    with patch.object(sys, 'argv', test_args):
        main()
    
    # Load CA cert
    ca_cert_data = (Path(temp_cert_dir) / "ca.crt").read_bytes()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_data)
    
    # Load server cert
    server_cert_data = (Path(temp_cert_dir) / "server.crt").read_bytes()
    server_cert = x509.load_pem_x509_certificate(server_cert_data)
    
    # Check CA has long validity (10 years)
    from datetime import datetime, UTC, timedelta
    ca_lifetime = ca_cert.not_valid_after_utc - ca_cert.not_valid_before_utc
    assert ca_lifetime > timedelta(days=3600)  # At least ~10 years
    
    # Check server cert has reasonable validity (~825 days)
    server_lifetime = server_cert.not_valid_after_utc - server_cert.not_valid_before_utc
    assert server_lifetime > timedelta(days=800)
    assert server_lifetime < timedelta(days=850)


def test_gen_certs_missing_out_argument():
    """Test gen_certs with missing --out argument"""
    test_args = ["prog"]
    
    with patch.object(sys, 'argv', test_args):
        with pytest.raises(SystemExit):
            main()


def test_gen_certs_pem_format(temp_cert_dir):
    """Test that certificates are in PEM format"""
    test_args = ["prog", "--out", temp_cert_dir]
    
    with patch.object(sys, 'argv', test_args):
        main()
    
    # Check CA cert is PEM format
    ca_cert_data = (Path(temp_cert_dir) / "ca.crt").read_bytes()
    assert ca_cert_data.startswith(b"-----BEGIN CERTIFICATE-----")
    assert ca_cert_data.strip().endswith(b"-----END CERTIFICATE-----")
    
    # Check CA key is PEM format
    ca_key_data = (Path(temp_cert_dir) / "ca.key").read_bytes()
    assert ca_key_data.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
