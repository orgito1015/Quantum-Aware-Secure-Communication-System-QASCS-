from __future__ import annotations
import argparse, socket
from qasccs.quantum_risk_engine.models import RiskRequest
from qasccs.quantum_risk_engine.policy import evaluate_risk
from .common import make_client_context

def main():
    ap = argparse.ArgumentParser(description="QASCS Secure Client (quantum-aware policy + TLS demo)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--data-lifetime-years", type=int, required=True)
    ap.add_argument("--data-classification", default="medium", choices=["low","medium","high","critical"])
    ap.add_argument("--scenario", default="moderate", choices=["conservative","moderate","aggressive"])
    ap.add_argument("--algorithm", default="ECC-P256", help="Crypto used today (default ECC-P256).")
    ap.add_argument("--message", default="hello from QASCS")
    args = ap.parse_args()

    req = RiskRequest(
        algorithm=args.algorithm,
        data_lifetime_years=args.data_lifetime_years,
        data_classification=args.data_classification,
        scenario=args.scenario,
    )
    resp = evaluate_risk(req)

    print("[client] Quantum Risk Engine decision:")
    print(f"         risk={resp.risk}, recommended_mode={resp.recommended_mode}, quantum_safe_until={resp.quantum_safe_until_year}")
    print(f"         rationale={resp.rationale}")

    if resp.recommended_mode in ("pqc", "hybrid"):
        print("[client] NOTE: PQC/hybrid enforcement needs OQS-OpenSSL (see docs/pqc-integration.md). Proceeding with classical TLS demo.")

    ctx = make_client_context()

    with socket.create_connection((args.host, args.port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=args.host) as tls:
            tls.sendall(args.message.encode("utf-8"))
            reply = tls.recv(4096).decode("utf-8", errors="replace")
            print(f"[client] Server replied: {reply}")

if __name__ == "__main__":
    main()
