# Architecture (QASCS)

## High-level flow
1. Client wants confidentiality for `N` years.
2. Client requests a **policy decision** from the Quantum Risk Engine.
3. Policy returns `recommended_mode` + risk details.
4. Client enforces the decision:
   - today: Python TLS (`classical`)
   - extension: OQS-OpenSSL (`pqc` / `hybrid`)
5. Secure channel established → data exchanged.
