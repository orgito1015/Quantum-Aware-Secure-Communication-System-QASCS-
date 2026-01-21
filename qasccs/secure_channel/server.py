from __future__ import annotations
import argparse, socket, ssl
from .common import make_server_context

def main():
    ap = argparse.ArgumentParser(description="QASCS Secure Server (Classical TLS demo)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    args = ap.parse_args()

    ctx = make_server_context()
    with socket.create_server((args.host, args.port)) as sock:
        print(f"[server] Listening on {args.host}:{args.port} (TLS)")
        while True:
            conn, addr = sock.accept()
            print(f"[server] Connection from {addr}")
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    data = tls.recv(4096)
                    if not data:
                        continue
                    msg = data.decode("utf-8", errors="replace")
                    print(f"[server] Received: {msg!r}")
                    tls.sendall(f"ACK (secure): {len(data)} bytes".encode("utf-8"))
            except ssl.SSLError as e:
                print(f"[server] TLS error: {e}")
            except Exception as e:
                print(f"[server] Error: {e}")

if __name__ == "__main__":
    main()
