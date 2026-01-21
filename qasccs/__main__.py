import sys
from qasccs.quantum_risk_engine.cli import main as risk_main

def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "risk":
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        risk_main()
    else:
        print("Usage:")
        print("  python -m qasccs risk --algorithm ECC-P256 --data-lifetime-years 10 --data-classification high")

if __name__ == "__main__":
    main()
