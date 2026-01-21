import pytest
import tempfile
import shutil
import socket
import ssl
import threading
import time
from pathlib import Path
from unittest.mock import patch
import sys

from qasccs.tools.gen_certs import main as gen_certs_main
from qasccs.secure_channel.common import make_server_context, make_client_context


@pytest.fixture
def temp_certs():
    """Create temporary certificates for testing"""
    temp_dir = tempfile.mkdtemp()
    cert_dir = Path(temp_dir) / "certs"
    cert_dir.mkdir()
    
    # Generate test certificates
    test_args = ["prog", "--out", str(cert_dir)]
    with patch.object(sys, 'argv', test_args):
        gen_certs_main()
    
    yield cert_dir
    shutil.rmtree(temp_dir)


def test_make_server_context_with_certs(temp_certs):
    """Test creating server SSL context"""
    # Temporarily patch the CERT_DIR to use test certs
    import qasccs.secure_channel.common as common_module
    original_cert_dir = common_module.CERT_DIR
    original_server_cert = common_module.SERVER_CERT
    original_server_key = common_module.SERVER_KEY
    
    try:
        common_module.CERT_DIR = temp_certs
        common_module.SERVER_CERT = temp_certs / "server.crt"
        common_module.SERVER_KEY = temp_certs / "server.key"
        
        ctx = make_server_context()
        
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    finally:
        common_module.CERT_DIR = original_cert_dir
        common_module.SERVER_CERT = original_server_cert
        common_module.SERVER_KEY = original_server_key


def test_make_client_context_with_certs(temp_certs):
    """Test creating client SSL context"""
    import qasccs.secure_channel.common as common_module
    original_cert_dir = common_module.CERT_DIR
    original_ca_cert = common_module.CA_CERT
    
    try:
        common_module.CERT_DIR = temp_certs
        common_module.CA_CERT = temp_certs / "ca.crt"
        
        ctx = make_client_context()
        
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        assert ctx.check_hostname is True
        assert ctx.verify_mode == ssl.CERT_REQUIRED
    finally:
        common_module.CERT_DIR = original_cert_dir
        common_module.CA_CERT = original_ca_cert


def test_tls_handshake_basic(temp_certs):
    """Test basic TLS handshake between client and server"""
    import qasccs.secure_channel.common as common_module
    original_cert_dir = common_module.CERT_DIR
    original_server_cert = common_module.SERVER_CERT
    original_server_key = common_module.SERVER_KEY
    original_ca_cert = common_module.CA_CERT
    
    try:
        common_module.CERT_DIR = temp_certs
        common_module.SERVER_CERT = temp_certs / "server.crt"
        common_module.SERVER_KEY = temp_certs / "server.key"
        common_module.CA_CERT = temp_certs / "ca.crt"
        
        server_ctx = make_server_context()
        client_ctx = make_client_context()
        
        # Create a server socket
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]
        
        server_error = None
        server_received = None
        
        def server_thread():
            nonlocal server_error, server_received
            try:
                conn, _ = server_sock.accept()
                with server_ctx.wrap_socket(conn, server_side=True) as tls:
                    data = tls.recv(1024)
                    server_received = data.decode("utf-8")
                    tls.sendall(b"ACK")
            except Exception as e:
                server_error = e
            finally:
                server_sock.close()
        
        thread = threading.Thread(target=server_thread)
        thread.start()
        
        # Give server time to start
        time.sleep(0.1)
        
        # Connect as client
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(("127.0.0.1", port))
        
        # Use qasccs.local or localhost which are in the SAN
        with client_ctx.wrap_socket(client_sock, server_hostname="localhost") as tls:
            tls.sendall(b"Hello TLS")
            reply = tls.recv(1024)
            assert reply == b"ACK"
        
        thread.join(timeout=2)
        
        assert server_error is None, f"Server error: {server_error}"
        assert server_received == "Hello TLS"
        
    finally:
        common_module.CERT_DIR = original_cert_dir
        common_module.SERVER_CERT = original_server_cert
        common_module.SERVER_KEY = original_server_key
        common_module.CA_CERT = original_ca_cert


def test_server_context_requires_tls12_minimum(temp_certs):
    """Test that server context requires TLS 1.2 minimum"""
    import qasccs.secure_channel.common as common_module
    original_cert_dir = common_module.CERT_DIR
    original_server_cert = common_module.SERVER_CERT
    original_server_key = common_module.SERVER_KEY
    
    try:
        common_module.CERT_DIR = temp_certs
        common_module.SERVER_CERT = temp_certs / "server.crt"
        common_module.SERVER_KEY = temp_certs / "server.key"
        
        ctx = make_server_context()
        
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    finally:
        common_module.CERT_DIR = original_cert_dir
        common_module.SERVER_CERT = original_server_cert
        common_module.SERVER_KEY = original_server_key


def test_client_context_requires_tls12_minimum(temp_certs):
    """Test that client context requires TLS 1.2 minimum"""
    import qasccs.secure_channel.common as common_module
    original_cert_dir = common_module.CERT_DIR
    original_ca_cert = common_module.CA_CERT
    
    try:
        common_module.CERT_DIR = temp_certs
        common_module.CA_CERT = temp_certs / "ca.crt"
        
        ctx = make_client_context()
        
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    finally:
        common_module.CERT_DIR = original_cert_dir
        common_module.CA_CERT = original_ca_cert


def test_client_verifies_server_cert(temp_certs):
    """Test that client properly verifies server certificate"""
    import qasccs.secure_channel.common as common_module
    original_cert_dir = common_module.CERT_DIR
    original_ca_cert = common_module.CA_CERT
    
    try:
        common_module.CERT_DIR = temp_certs
        common_module.CA_CERT = temp_certs / "ca.crt"
        
        ctx = make_client_context()
        
        # Verify mode should be CERT_REQUIRED
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        
        # Hostname checking should be enabled
        assert ctx.check_hostname is True
    finally:
        common_module.CERT_DIR = original_cert_dir
        common_module.CA_CERT = original_ca_cert
