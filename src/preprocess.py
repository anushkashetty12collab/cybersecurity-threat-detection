"""
Task 1 - Step 2: Cleaning + feature engineering.

Context features are computed per source IP over 5-minute tumbling windows
(failed logins, unique ports, ...) and per (source, destination) pair over 1 hour
(connection count, inter-arrival regularity -> beaconing).

NOTE: `severity` and `attack_type` are NOT used as features: severity is assigned
by the generator with knowledge of the label, so using it would be label leakage.

Run: python -m src.preprocess
"""
from pathlib import Path

import numpy as np
import pandas as pd

FEATURES = [
    "hour", "is_off_hours", "is_weekend", "src_internal", "dst_internal", "port",
    "log_bytes_out", "status_failed", "is_admin_action", "user_is_admin",
    "failed_logins_5m", "unique_ports_5m", "unique_dests_5m", "events_5m",
    "pair_conn_1h", "pair_interval_std_1h", "pair_interval_mean_1h",
    "evt_login", "evt_file_access", "evt_network_conn", "evt_admin_action",
]


def clean(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp", "source_ip", "dest_ip", "event_type", "status"])
    df = df.drop_duplicates(subset=["timestamp", "source_ip", "dest_ip", "event_type", "port", "user"])
    df["bytes_out"] = pd.to_numeric(df["bytes_out"], errors="coerce").fillna(0).clip(lower=0)
    df["port"] = pd.to_numeric(df["port"], errors="coerce").fillna(0).astype(int)
    return df.sort_values("timestamp").reset_index(drop=True)


def add_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    ts = df["timestamp"]
    df["hour"] = ts.dt.hour
    df["is_off_hours"] = ((df["hour"] < 7) | (df["hour"] >= 20)).astype(int)
    df["is_weekend"] = (ts.dt.dayofweek >= 5).astype(int)
    df["src_internal"] = df["source_ip"].str.startswith("10.").astype(int)
    df["dst_internal"] = df["dest_ip"].str.startswith("10.").astype(int)
    df["log_bytes_out"] = np.log1p(df["bytes_out"])
    df["status_failed"] = (df["status"] == "failure").astype(int)
    df["is_admin_action"] = (df["event_type"] == "admin_action").astype(int)
    df["user_is_admin"] = df["user"].str.startswith("admin").astype(int)
    for e in ["login", "file_access", "network_conn", "admin_action"]:
        df[f"evt_{e}"] = (df["event_type"] == e).astype(int)

    # --- per-source 5-minute window features
    df["win5"] = ts.dt.floor("5min")
    df["_failed_login"] = ((df["event_type"] == "login") & (df["status"] == "failure")).astype(int)
    g = df.groupby(["source_ip", "win5"])
    df["failed_logins_5m"] = g["_failed_login"].transform("sum")
    df["unique_ports_5m"] = g["port"].transform("nunique")
    df["unique_dests_5m"] = g["dest_ip"].transform("nunique")
    df["events_5m"] = g["event_id"].transform("count")

    # --- per (source, dest) 1-hour pair features (beaconing regularity)
    df["hour_bucket"] = ts.dt.floor("1h")
    df["_gap"] = df.groupby(["source_ip", "dest_ip"])["timestamp"].diff().dt.total_seconds()
    gp = df.groupby(["source_ip", "dest_ip", "hour_bucket"])
    df["pair_conn_1h"] = gp["event_id"].transform("count")
    # fill with large sentinel when there are <5 events: "no regular pattern"
    df["pair_interval_std_1h"] = gp["_gap"].transform("std").fillna(9999)
    df["pair_interval_mean_1h"] = gp["_gap"].transform("mean").fillna(9999)
    df.loc[df["pair_conn_1h"] < 5, ["pair_interval_std_1h", "pair_interval_mean_1h"]] = 9999
    return df.drop(columns=["_failed_login", "_gap"])


def main():
    raw = pd.read_csv("data/raw/logs.csv")
    df = add_features(clean(raw))
    out = Path("data/processed/features.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print(f"Saved {len(df):,} rows, {len(FEATURES)} features -> {out}")


if __name__ == "__main__":
    main()
