"""
Task 1 - Step 1: Synthetic cybersecurity log generator.

Creates mostly-normal traffic (with some deliberately "hard" benign events that
will cause false positives) and injects 5 attack patterns:
  brute_force, port_scan, priv_escalation, exfiltration, c2_beaconing

Output: data/raw/logs.csv
Run:    python -m src.generate_logs
"""
import random
from pathlib import Path

import numpy as np
import pandas as pd

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

START = pd.Timestamp("2026-09-01 00:00:00")
DAYS = 7
N_NORMAL = 25_000

ASSETS = {  # asset name -> internal IP
    "web-01": "10.0.1.10", "web-02": "10.0.1.11",
    "db-01": "10.0.2.20", "db-02": "10.0.2.21",
    "auth-01": "10.0.3.30", "file-01": "10.0.4.40",
    "mail-01": "10.0.5.50", "backup-01": "10.0.6.60",
}
WORKSTATIONS = [f"10.0.10.{i}" for i in range(2, 60)]
USERS = [f"user{i:02d}" for i in range(1, 41)]
ADMINS = ["admin_ravi", "admin_meera", "admin_john"]
EXTERNAL_POOL = [f"{random.choice([45, 91, 103, 185, 194, 203])}."
                 f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                 for _ in range(300)]
COMMON_PORTS = [22, 80, 443, 445, 3306, 5432, 3389, 25, 53]

COLUMNS = ["timestamp", "source_ip", "dest_ip", "asset", "user", "event_type",
           "status", "port", "bytes_out", "severity", "is_suspicious", "attack_type"]


def rand_ts(day_weighted=True):
    """Random timestamp; normal traffic is heavier in working hours."""
    day = random.randint(0, DAYS - 1)
    if day_weighted and random.random() < 0.85:
        sec = int(np.random.normal(13 * 3600, 3 * 3600))
        sec = min(max(sec, 8 * 3600), 19 * 3600)
    else:
        sec = random.randint(0, 86399)
    return START + pd.Timedelta(days=day, seconds=sec)


def ev(ts, src, asset, user, etype, status, port, nbytes, sev, label=0, atype="normal", dst=None):
    return dict(timestamp=ts, source_ip=src, dest_ip=dst or ASSETS[asset], asset=asset,
                user=user, event_type=etype, status=status, port=port,
                bytes_out=int(nbytes), severity=sev, is_suspicious=label, attack_type=atype)


# ---------------------------------------------------------------- normal ----
def gen_normal(n):
    rows = []
    for _ in range(n):
        ts = rand_ts()
        src = random.choice(WORKSTATIONS)
        asset = random.choice(list(ASSETS))
        user = random.choice(USERS)
        r = random.random()
        if r < 0.40:    # login
            status = "failure" if random.random() < 0.04 else "success"  # typos
            rows.append(ev(ts, src, asset, user, "login", status, random.choice([22, 443, 3389]),
                           np.random.lognormal(5, 0.5), "low" if status == "success" else "medium"))
        elif r < 0.75:  # file access
            rows.append(ev(ts, src, "file-01", user, "file_access", "success", 445,
                           np.random.lognormal(8, 1.2), "low"))
        elif r < 0.93:  # normal network connection (some to external sites)
            ext = random.random() < 0.35
            dst = random.choice(EXTERNAL_POOL[:40]) if ext else None
            rows.append(ev(ts, src, asset, user, "network_conn", "success",
                           443 if ext else random.choice(COMMON_PORTS),
                           np.random.lognormal(7.5, 1.0), "low", dst=dst))
        else:           # admin action by real admins, mostly in business hours
            rows.append(ev(ts, random.choice(WORKSTATIONS[:5]), asset, random.choice(ADMINS),
                           "admin_action", "success", 22, np.random.lognormal(6, 0.5), "medium"))
    return rows


def gen_hard_benign():
    """Benign events that LOOK suspicious -> realistic source of false positives."""
    rows = []
    # nightly backups: large, off-hours internal transfers
    for d in range(DAYS):
        ts = START + pd.Timedelta(days=d, hours=2, minutes=random.randint(0, 30))
        for _ in range(random.randint(3, 6)):
            rows.append(ev(ts, ASSETS["backup-01"], "file-01", "svc_backup", "network_conn", "success",
                           445, np.random.lognormal(15, 0.6), "low"))
            ts += pd.Timedelta(minutes=random.randint(1, 5))
    # authorised internal vulnerability scanner (many ports quickly)
    for d in random.sample(range(DAYS), 3):
        ts = START + pd.Timedelta(days=d, hours=22)
        for p in random.sample(range(1, 2000), random.randint(50, 120)):
            rows.append(ev(ts, "10.0.10.99", "web-01", "svc_scanner", "network_conn", "failure", p, 60, "low"))
            ts += pd.Timedelta(seconds=random.uniform(0.5, 3))
    # employees / service accounts failing logins repeatedly, then succeeding
    for _ in range(30):
        ts, src, u = rand_ts(), random.choice(WORKSTATIONS), random.choice(USERS)
        for _ in range(random.randint(4, 14)):
            rows.append(ev(ts, src, "auth-01", u, "login", "failure", 443, 300, "medium"))
            ts += pd.Timedelta(seconds=random.randint(3, 25))
        rows.append(ev(ts, src, "auth-01", u, "login", "success", 443, 300, "low"))
    # admins working late
    for _ in range(25):
        ts = START + pd.Timedelta(days=random.randint(0, DAYS - 1), hours=random.choice([21, 22, 23, 0, 1]))
        rows.append(ev(ts, random.choice(WORKSTATIONS[:5]), random.choice(list(ASSETS)), random.choice(ADMINS),
                       "admin_action", "success", 22, np.random.lognormal(6.5, 0.8), "medium"))
    # periodic monitoring / update heartbeats (regular like C2, but legitimate)
    for i in range(4):
        host, dst = random.choice(WORKSTATIONS), EXTERNAL_POOL[i]
        ts = rand_ts(False)
        interval = random.choice([60, 120, 300])
        for _ in range(random.randint(30, 60)):
            rows.append(ev(ts, host, "web-01", "svc_monitor", "network_conn", "success", 443,
                           np.random.normal(200, 40), "low", dst=dst))
            ts += pd.Timedelta(seconds=interval + random.uniform(-3, 3))
    # legitimate large uploads to external services (cloud storage, video calls)
    for _ in range(40):
        rows.append(ev(rand_ts(), random.choice(WORKSTATIONS), "file-01", random.choice(USERS), "network_conn",
                       "success", 443, np.random.lognormal(14.5, 0.9), "low", dst=random.choice(EXTERNAL_POOL[:40])))
    return rows


# --------------------------------------------------------------- attacks ----
def attack_brute_force():
    rows = []
    # 5 loud + 8 slow ("low and slow") campaigns
    for loud in [True] * 5 + [False] * 8:
        ts = rand_ts(False)
        src = random.choice(EXTERNAL_POOL[100:])
        asset = random.choice(["auth-01", "web-01", "db-01"])
        user = random.choice(USERS + ADMINS)
        n = random.randint(20, 60) if loud else random.randint(8, 25)
        for _ in range(n):
            rows.append(ev(ts, src, asset, user, "login", "failure", random.choice([22, 3389]),
                           250, "high", 1, "brute_force"))
            ts += pd.Timedelta(seconds=random.uniform(1, 6) if loud else random.uniform(8, 40))
        if random.random() < 0.6:  # successful compromise
            rows.append(ev(ts, src, asset, user, "login", "success", 22, 300, "critical", 1, "brute_force"))
    return rows


def attack_port_scan():
    rows = []
    for loud in [True] * 3 + [False] * 6:
        ts = rand_ts(False)
        src = random.choice(EXTERNAL_POOL[100:])
        asset = random.choice(list(ASSETS))
        n = random.randint(60, 150) if loud else random.randint(25, 70)
        for p in random.sample(range(1, 10000), n):
            rows.append(ev(ts, src, asset, "unknown", "network_conn", "failure", p, 60, "medium", 1, "port_scan"))
            ts += pd.Timedelta(seconds=random.uniform(0.3, 1.5) if loud else random.uniform(3, 20))
    return rows


def attack_priv_escalation(n=25):
    rows = []
    for _ in range(n):
        business = random.random() < 0.4          # some happen during working hours
        hour = random.choice([9, 11, 14, 16]) if business else random.choice([0, 1, 2, 3, 4, 23])
        ts = START + pd.Timedelta(days=random.randint(0, DAYS - 1), hours=hour, minutes=random.randint(0, 59))
        src = random.choice(WORKSTATIONS)
        # 40% use a compromised admin account (looks like a legit admin)
        user = random.choice(ADMINS) if random.random() < 0.4 else random.choice(USERS)
        asset = random.choice(["db-01", "db-02", "auth-01"])
        for k in range(random.randint(1, 2)):
            rows.append(ev(ts + pd.Timedelta(seconds=30 * k), src, asset, user, "admin_action", "success", 22,
                           np.random.lognormal(7, 0.6), "high", 1, "priv_escalation"))
    return rows


def attack_exfiltration(n=10):
    rows = []
    for i in range(n):
        ts = START + pd.Timedelta(days=i % DAYS, seconds=random.randint(0, 80000))
        src = ASSETS[random.choice(["db-01", "db-02", "file-01"])]
        asset = random.choice(["db-01", "db-02", "file-01"])
        dst = random.choice(EXTERNAL_POOL[100:])
        for _ in range(random.randint(2, 5)):
            rows.append(ev(ts, src, asset, random.choice(USERS), "network_conn", "success", 443,
                           np.random.lognormal(14.8, 0.8), "critical", 1, "exfiltration", dst=dst))
            ts += pd.Timedelta(minutes=random.randint(1, 6))
    return rows


def attack_c2_beaconing(n_hosts=8):
    rows = []
    for i in range(n_hosts):
        ts = START + pd.Timedelta(days=i % DAYS, seconds=random.randint(0, 70000))
        src = random.choice(WORKSTATIONS)
        c2 = random.choice(EXTERNAL_POOL[100:])
        interval = random.choice([30, 60, 120, 300])
        jitter = random.uniform(0.02, 0.3)        # attackers add jitter to evade detection
        for _ in range(random.randint(25, 50)):
            rows.append(ev(ts, src, random.choice(["web-01", "mail-01"]), random.choice(USERS),
                           "network_conn", "success", 443, abs(np.random.normal(210, 45)), "high",
                           1, "c2_beaconing", dst=c2))
            ts += pd.Timedelta(seconds=interval * (1 + random.uniform(-jitter, jitter)))
    return rows


def main():
    rows = (gen_normal(N_NORMAL) + gen_hard_benign() + attack_brute_force() + attack_port_scan()
            + attack_priv_escalation() + attack_exfiltration() + attack_c2_beaconing())
    df = pd.DataFrame(rows, columns=COLUMNS).sort_values("timestamp").reset_index(drop=True)
    df["event_id"] = np.arange(len(df))
    out = Path("data/raw/logs.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print(f"Saved {len(df):,} events -> {out}")
    print(f"Suspicious: {df.is_suspicious.sum():,} ({df.is_suspicious.mean():.1%})")
    print(df.attack_type.value_counts().to_string())


if __name__ == "__main__":
    main()
