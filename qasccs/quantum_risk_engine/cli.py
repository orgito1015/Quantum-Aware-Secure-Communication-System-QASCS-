import argparse, json
from .models import RiskRequest
from .policy import evaluate_risk

def main():
    ap = argparse.ArgumentParser(description="Quantum Risk Engine (QASCS)")
    ap.add_argument("--algorithm", required=True)
    ap.add_argument("--data-lifetime-years", type=int, required=True)
    ap.add_argument("--data-classification", default="medium", choices=["low","medium","high","critical"])
    ap.add_argument("--scenario", default="moderate", choices=["conservative","moderate","aggressive"])
    args = ap.parse_args()

    req = RiskRequest(
        algorithm=args.algorithm,
        data_lifetime_years=args.data_lifetime_years,
        data_classification=args.data_classification,
        scenario=args.scenario,
    )
    resp = evaluate_risk(req)
    print(json.dumps(resp.model_dump(), indent=2))

if __name__ == "__main__":
    main()
