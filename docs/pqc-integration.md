# PQC / Hybrid TLS integration

Python's `ssl` cannot do post-quantum TLS directly.

## Recommended path: OQS-OpenSSL + oqsprovider
Use `openssl s_server` / `openssl s_client` with PQC/hybrid groups.

This repo keeps **one policy engine** (quantum risk) and switches the enforcement layer:
- `classical` → Python TLS
- `pqc/hybrid` → OQS-OpenSSL endpoints (wrapper placeholder in `qasccs/tools/pqc_tls.py`)
