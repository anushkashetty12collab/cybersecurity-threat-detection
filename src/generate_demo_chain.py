"""
Adds ONE multi-stage attack chain on db-01 to the existing logs so that the
correlation rules can be demonstrated on a held-out day (not used for training):

  03:00 port scan -> 03:08 brute force -> 03:10 successful login (user17)
  -> 03:22 admin actions by non-admin account -> 03:35 data exfiltration from db-01

Output: data/raw/logs_demo.csv      Run: python -m src.generate_demo_chain
"""
import numpy as np
import pandas as pd

from src.generate_logs import ASSETS, COLUMNS, START, ev

np.random.seed(7)
ATTACKER, EXFIL_DST, ASSET, USER = "203.0.113.77", "198.51.100.23", "db-01", "user17"


def chain():
    t0 = START + pd.Timedelta(days=6, hours=3)
    rows, ts = [], t0
    for p in np.random.choice(np.arange(1, 10000), 90, replace=False):
        rows.append(ev(ts, ATTACKER, ASSET, "unknown", "network_conn", "failure", int(p), 60, "medium", 1, "port_scan"))
        ts += pd.Timedelta(seconds=1)
    ts = t0 + pd.Timedelta(minutes=8)
    for _ in range(45):
        rows.append(ev(ts, ATTACKER, ASSET, USER, "login", "failure", 22, 250, "high", 1, "brute_force"))
        ts += pd.Timedelta(seconds=3)
    rows.append(ev(ts, ATTACKER, ASSET, USER, "login", "success", 22, 300, "critical", 1, "brute_force"))
    ts = t0 + pd.Timedelta(minutes=22)
    for k in range(2):
        rows.append(ev(ts + pd.Timedelta(seconds=30 * k), ATTACKER, ASSET, USER, "admin_action", "success", 22,
                       2000, "high", 1, "priv_escalation"))
    ts = t0 + pd.Timedelta(minutes=35)
    for _ in range(4):
        rows.append(ev(ts, ASSETS[ASSET], ASSET, USER, "network_conn", "success", 443,
                       np.random.lognormal(17, 0.3), "critical", 1, "exfiltration", dst=EXFIL_DST))
        ts += pd.Timedelta(minutes=2)
    return rows


if __name__ == "__main__":
    base = pd.read_csv("data/raw/logs.csv", parse_dates=["timestamp"]).drop(columns=["event_id"])
    df = pd.concat([base, pd.DataFrame(chain(), columns=COLUMNS)]).sort_values("timestamp").reset_index(drop=True)
    df["event_id"] = np.arange(len(df))
    df.to_csv("data/raw/logs_demo.csv", index=False)
    print(f"Saved {len(df):,} events (incl. injected chain on {ASSET}) -> data/raw/logs_demo.csv")
