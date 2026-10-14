"""
Task 2 - Step 1: score events with the trained model and classify each alert.

The ML model is binary (suspicious / normal). To correlate alerts we need to know
WHAT kind of suspicious activity each alert is, so every alerted event is classified
with transparent feature-based rules and given a human-readable reason.

NOTE: the raw `severity` column is ignored (it comes from the generator). Alert
severity is derived from the finding type here.
"""
import joblib
import numpy as np
import pandas as pd

from src.preprocess import add_features, clean

MODEL_PATH = "models/model.joblib"
REQUIRED_COLUMNS = ["timestamp", "source_ip", "dest_ip", "asset", "user",
                    "event_type", "status", "port", "bytes_out"]

FINDING_SEVERITY = {
    "port_scan": "medium", "brute_force": "high", "login_success": "critical",
    "c2_beaconing": "high", "exfiltration": "critical",
    "priv_escalation": "high", "anomalous_activity": "medium",
}

# classification thresholds (tune on your data)
MIN_FAILED_LOGINS = 5
MIN_SCAN_PORTS = 20
MIN_EXFIL_BYTES = 500_000
MAX_BEACON_CV = 0.35          # std/mean of inter-arrival times
MIN_PRIOR_FAILURES = 3        # failures before a success to call it "login_success"
LOOKBACK = pd.Timedelta(minutes=10)


def load_model(path: str = MODEL_PATH) -> dict:
    return joblib.load(path)


def score_events(raw: pd.DataFrame, bundle: dict | None = None) -> pd.DataFrame:
    bundle = bundle or load_model()
    raw = raw.copy()
    if "event_id" not in raw.columns:
        raw["event_id"] = np.arange(len(raw))
    df = add_features(clean(raw))
    proba = bundle["model"].predict_proba(df[bundle["features"]])[:, 1]
    df["model_score"] = proba
    df["predicted"] = (proba >= bundle["threshold"]).astype(int)
    return df


def classify_alerts(df: pd.DataFrame) -> pd.DataFrame:
    alerts = df[df["predicted"] == 1].copy()
    if alerts.empty:
        return alerts.assign(finding_type=[], alert_severity=[], reason=[], prior_failures=[])

    ext_dst = alerts["dst_internal"] == 0
    mean_gap = alerts["pair_interval_mean_1h"].replace(0, np.nan)
    cv = alerts["pair_interval_std_1h"] / mean_gap
    is_net = alerts["event_type"] == "network_conn"
    conditions = [
        alerts["event_type"] == "admin_action",
        (alerts["event_type"] == "login") & (alerts["status"] == "success"),
        (alerts["event_type"] == "login") & (alerts["status"] == "failure")
        & (alerts["failed_logins_5m"] >= MIN_FAILED_LOGINS),
        is_net & (alerts["status"] == "failure") & (alerts["unique_ports_5m"] >= MIN_SCAN_PORTS),
        is_net & ext_dst & (alerts["src_internal"] == 1) & (alerts["bytes_out"] >= MIN_EXFIL_BYTES),
        is_net & ext_dst & (alerts["pair_conn_1h"] >= 5) & (cv <= MAX_BEACON_CV),
    ]
    names = ["priv_escalation", "login_success", "brute_force", "port_scan", "exfiltration", "c2_beaconing"]
    alerts["finding_type"] = np.select(conditions, names, default="anomalous_activity")

    # a successful login only matters if failures from the same source preceded it
    alerts["prior_failures"] = 0
    fails = df[(df["event_type"] == "login") & (df["status"] == "failure")]
    for idx in alerts.index[alerts["finding_type"] == "login_success"]:
        r = alerts.loc[idx]
        w = fails[(fails["source_ip"] == r["source_ip"]) & (fails["asset"] == r["asset"])
                  & (fails["timestamp"] < r["timestamp"]) & (fails["timestamp"] >= r["timestamp"] - LOOKBACK)]
        alerts.at[idx, "prior_failures"] = len(w)
    weak = (alerts["finding_type"] == "login_success") & (alerts["prior_failures"] < MIN_PRIOR_FAILURES)
    alerts.loc[weak, "finding_type"] = "anomalous_activity"

    alerts["alert_severity"] = alerts["finding_type"].map(FINDING_SEVERITY)
    alerts["reason"] = alerts.apply(_reason, axis=1)
    return alerts.sort_values("timestamp")


def _reason(r) -> str:
    base = f"model score {r.model_score:.2f}"
    ft = r.finding_type
    if ft == "brute_force":
        return f"{base}; {int(r.failed_logins_5m)} failed logins from this source in a 5-min window"
    if ft == "login_success":
        return f"{base}; successful login preceded by {int(r.prior_failures)} failures in 10 min"
    if ft == "port_scan":
        return f"{base}; {int(r.unique_ports_5m)} distinct ports probed by this source in a 5-min window"
    if ft == "exfiltration":
        return f"{base}; {int(r.bytes_out):,} bytes sent from an internal host to an external IP"
    if ft == "c2_beaconing":
        return (f"{base}; {int(r.pair_conn_1h)} connections to the same external IP in 1 h, "
                f"interval ~{r.pair_interval_mean_1h:.0f}s (std {r.pair_interval_std_1h:.1f}s)")
    if ft == "priv_escalation":
        who = "non-admin account" if not r.user_is_admin else "admin account"
        when = "off-hours" if r.is_off_hours else "business hours"
        return f"{base}; administrative action by {who} ({r.user}) during {when}"
    return f"{base}; flagged by model, no specific rule matched"
