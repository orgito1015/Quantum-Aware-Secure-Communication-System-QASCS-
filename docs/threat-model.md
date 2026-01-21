# Threat model (Quantum-aware)

This project explicitly models a **quantum-capable adversary** and focuses on **long-term confidentiality**.

## Quantum algorithms
- **Shor's algorithm** breaks RSA/DH/ECC → recorded sessions become decryptable once feasible.
- **Grover's algorithm** reduces symmetric security roughly by half (in bits).

## Design decision
Use the **Quantum Risk Engine** to decide when to require `classical`, `pqc`, or `hybrid`.
