# QASCS — Quantum‑Aware Secure Communication System

A **single, focused project** that combines:

- **Quantum**: explicit threat model (Shor/Grover), and a **Quantum Risk Engine** that decides whether a crypto setup is *quantum‑safe for a data lifetime*.
- **Cybersecurity**: a working **secure client ↔ server** channel (TLS) with **crypto‑agility** (policy decides classical vs PQC/hybrid).

This repo is designed to be:
- **Runnable today** in *Classical TLS* mode (pure Python).
- **Extendable** to **Post‑Quantum / Hybrid TLS** using OQS‑OpenSSL (documented integration path).

---

## Quick start (Classical TLS demo)

### 1) Create a venv + install deps
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .  # Install the qasccs package in editable mode
```

### 2) Generate a self‑signed cert (dev only)
```bash
python -m qasccs.tools.gen_certs --out qasccs/secure_channel/certs
```

### 3) Run server (Terminal A)
```bash
python -m qasccs.secure_channel.server --host 127.0.0.1 --port 8443
```

### 4) Run client (Terminal B)
```bash
python -m qasccs.secure_channel.client --host 127.0.0.1 --port 8443 --data-lifetime-years 10 --data-classification high
```

You will see:
- the client asks the **Quantum Risk Engine** for a policy decision
- the channel is established using **classical TLS**
- messages are exchanged securely

---

## Quantum part (what’s actually “quantum” here?)

- `qasccs/quantum_risk_engine/` models a quantum adversary:
  - **Shor** breaks RSA/ECC (public‑key)
  - **Grover** reduces symmetric security (e.g., AES‑256 → ~128)
- It outputs a **machine‑readable decision**:
  - `risk: LOW/MEDIUM/HIGH`
  - `recommended_mode: classical | pqc | hybrid`
  - `quantum_safe_until_year`

See: `docs/threat-model.md`

---

## Post‑Quantum / Hybrid TLS (optional extension)

Pure Python cannot do PQC TLS alone. This repo includes a clean path:
- use **OQS‑OpenSSL** (OpenSSL + oqsprovider) and run `openssl s_server`/`s_client`
- keep the **same Quantum Risk Engine policy** to decide when to require PQC/hybrid

See: `docs/pqc-integration.md`

---

## Run tests
```bash
# Make sure the package is installed first
pip install -e .
pytest -q
```

---

## Disclaimer
This project is for **learning/research**. The default certificate generation is **dev‑only** and not production‑ready.
