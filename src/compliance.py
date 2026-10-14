"""
Task 3: map findings to NIST CSF 2.0 (+ ISO 27001:2022) using a JSON lookup table.

Per finding output: control references, supporting evidence, risk level, remediation.
Risk level = finding severity, raised one level if the affected asset is high-criticality.
"""
import json
from pathlib import Path

LEVELS = ["Low", "Medium", "High", "Critical"]
DEFAULT_MAPPING = "data/compliance/nist_csf_2_0.json"


def load_mapping(path: str = DEFAULT_MAPPING) -> dict:
    with open(Path(path)) as f:
        return json.load(f)


def risk_level(finding: dict, mapping: dict) -> tuple[str, str]:
    base = LEVELS.index(finding["max_alert_severity"].capitalize())
    crit_assets = [a for a in finding["assets"] if mapping["asset_criticality"].get(a) == "high"]
    if crit_assets and base < 3:
        return LEVELS[base + 1], (f"{finding['max_alert_severity']} severity raised one level: "
                                  f"affects high-criticality asset(s) {', '.join(crit_assets)}")
    return LEVELS[base], f"{finding['max_alert_severity']} severity"


def map_incident(incident: dict, mapping: dict) -> list[dict]:
    out = []
    multi = len([s for s in incident["stages"] if s != "anomalous_activity"]) >= 2
    for f in incident["findings"]:
        entry = mapping["findings"].get(f["finding_type"], mapping["findings"]["anomalous_activity"])
        level, why = risk_level(f, mapping)
        controls = list(entry["nist_csf_2_0"]) + (mapping["multi_stage_extra_controls"] if multi else [])
        out.append({
            "finding_id": f["finding_id"], "incident_id": incident["incident_id"],
            "finding_type": f["finding_type"], "title": entry["title"],
            "framework": mapping["framework"], "controls": controls,
            "iso_27001_2022": entry["iso_27001_2022"],
            "affected_assets": f["assets"], "source_ips": f["source_ips"],
            "evidence": f["evidence"], "sample_event_ids": f["sample_event_ids"],
            "risk_level": level, "risk_rationale": why,
            "remediation": entry["remediation"],
        })
    return out
