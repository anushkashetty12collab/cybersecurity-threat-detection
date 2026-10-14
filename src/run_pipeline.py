"""
End-to-end: logs -> ML detection -> alert classification -> incident correlation -> compliance mapping.

Run: python -m src.run_pipeline --input data/raw/logs_demo.csv --holdout
     (--holdout analyses only the time window the model never saw during training)
"""
import argparse
import json
import json as _json
from pathlib import Path

import numpy as np
import pandas as pd

from src.compliance import load_mapping, map_incident
from src.correlate import correlate
from src.detect import classify_alerts, load_model, score_events


def _default(o):
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return float(o)
    return str(o)


def analyze(raw: pd.DataFrame, since=None, bundle=None, mapping=None) -> dict:
    """Reusable by the Day 3 API."""
    scored = score_events(raw, bundle)
    if since is not None:
        scored = scored[scored["timestamp"] > pd.Timestamp(since)]
    alerts = classify_alerts(scored)
    incidents = correlate(alerts)
    mapping = mapping or load_mapping()
    findings = [f for inc in incidents for f in map_incident(inc, mapping)]
    return {"scored": scored, "alerts": alerts, "incidents": incidents, "findings": findings}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/raw/logs_demo.csv")
    ap.add_argument("--holdout", action="store_true", help="only analyse the held-out test window")
    ap.add_argument("--out", default="reports")
    args = ap.parse_args()

    since = None
    if args.holdout:
        since = _json.load(open("models/metrics.json"))["split_timestamp"]
    res = analyze(pd.read_csv(args.input), since=since, bundle=load_model())
    alerts, incidents, findings = res["alerts"], res["incidents"], res["findings"]

    out = Path(args.out); out.mkdir(exist_ok=True)
    keep = ["event_id", "timestamp", "source_ip", "dest_ip", "asset", "user", "event_type", "status",
            "finding_type", "alert_severity", "model_score", "reason"]
    alerts[keep].to_csv(out / "alerts.csv", index=False)
    json.dump(incidents, open(out / "incidents.json", "w"), indent=2, default=_default)
    json.dump(findings, open(out / "compliance_findings.json", "w"), indent=2, default=_default)

    print(f"Events analysed: {len(res['scored']):,} | alerts: {len(alerts):,} | "
          f"incidents: {len(incidents)} | compliance findings: {len(findings)}\n")
    print("Incidents by severity:", pd.Series([i['severity'] for i in incidents]).value_counts().to_dict())
    multi = [i for i in incidents if len([s for s in i["stages"] if s != "anomalous_activity"]) >= 2]
    print(f"Multi-stage incidents: {len(multi)}\n")
    for i in multi:
        print(f"{i['incident_id']} [{i['severity'].upper()}] {i['start']} -> {i['end']}")
        print("  stages:", " -> ".join(i["stages"]), "| rules:", ", ".join(i["correlation_rules"]))
        print("  why:", i["severity_reason"])
        print("  explanation:", i["explanation"], "\n")

    if "attack_type" in alerts.columns:   # sanity check against generator ground truth
        print("Alert classification vs ground truth (rows = my finding_type, cols = true attack_type):")
        print(pd.crosstab(alerts["finding_type"], alerts["attack_type"]).to_string())


if __name__ == "__main__":
    main()
