"""
Task 2 - Step 2: group alerts into incidents.

Rule A  same_source_ip_15m : alerts from the same source IP, each within 15 min of the previous one.
Rule B  asset_chain_30m    : alerts on the same asset that progress along the kill chain
                             (port_scan -> brute_force -> login_success -> priv_escalation -> exfiltration)
                             within 30 min. This links an attacker's IP to later activity that comes
                             FROM the asset itself (e.g. data leaving the compromised DB server).
Alerts linked by either rule (transitively) form one incident (union-find).

Incident severity = max alert severity, raised one level when >= 2 distinct stages are present.
"""
from collections import defaultdict

import numpy as np
import pandas as pd


def _t(ts):
    return pd.Timestamp(ts).floor("s").strftime("%Y-%m-%d %H:%M:%S")

SAME_SRC_GAP = np.timedelta64(15, "m")
ASSET_CHAIN_GAP = np.timedelta64(30, "m")
STAGE_ORDER = {"port_scan": 1, "brute_force": 2, "login_success": 3, "priv_escalation": 4, "exfiltration": 5}
SEV_LEVELS = ["low", "medium", "high", "critical"]
SEV_RANK = {s: i + 1 for i, s in enumerate(SEV_LEVELS)}


class UnionFind:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


# ------------------------------------------------------------ text helpers --
def _join(series, k=3):
    vals = sorted({str(v) for v in series})
    return ", ".join(vals[:k]) + (f" +{len(vals) - k} more" if len(vals) > k else "")


def _fmt_dur(sec):
    sec = int(round(sec))
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m {sec % 60}s"
    return f"{sec // 3600}h {(sec % 3600) // 60}m"


def _fmt_bytes(n):
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024


def describe(ft, g):
    n, srcs, assets, users = len(g), _join(g.source_ip), _join(g.asset), _join(g.user)
    dur = _fmt_dur((g.timestamp.max() - g.timestamp.min()).total_seconds())
    if ft == "brute_force":
        return f"{n} failed logins from {srcs} against {assets} (account: {users}) within {dur}"
    if ft == "login_success":
        return (f"successful login to {assets} by {users} from {srcs} "
                f"after {int(g.prior_failures.max())} failed attempts in the preceding 10 min")
    if ft == "port_scan":
        return f"{n} blocked connection attempts across {g.port.nunique()} distinct ports on {assets} from {srcs} within {dur}"
    if ft == "c2_beaconing":
        interval = g.pair_interval_mean_1h.replace(9999, np.nan).median()
        return (f"{n} outbound connections from {srcs} to {_join(g.dest_ip)} at a regular ~{interval:.0f}s interval "
                f"(small payloads, ~{g.bytes_out.mean():.0f} bytes each)")
    if ft == "exfiltration":
        return f"{n} large outbound transfers ({_fmt_bytes(g.bytes_out.sum())} total) from {assets} ({srcs}) to external {_join(g.dest_ip)}"
    if ft == "priv_escalation":
        nonadmin = int((~g.user.str.startswith("admin")).sum())
        off = int(g.is_off_hours.sum())
        return (f"{n} administrative action(s) on {assets} by {users} from {srcs} "
                f"({nonadmin} by non-admin accounts, {off} outside business hours)")
    return f"{n} anomalous events from {srcs} on {assets}"


# --------------------------------------------------------------- correlate --
def correlate(alerts: pd.DataFrame) -> list[dict]:
    if alerts.empty:
        return []
    a = alerts.sort_values("timestamp").reset_index(drop=True)
    ts = a["timestamp"].to_numpy()
    uf, links = UnionFind(len(a)), []

    # Rule A: same source IP, gap <= 15 min
    for idx in a.groupby("source_ip").indices.values():
        idx = sorted(idx)
        for i, j in zip(idx, idx[1:]):
            if ts[j] - ts[i] <= SAME_SRC_GAP:
                uf.union(i, j)
                links.append((i, "same_source_ip_15m"))

    # Rule B: same asset, kill-chain progression within 30 min
    stage = a["finding_type"].map(STAGE_ORDER).fillna(0).astype(int).to_numpy()
    for idx in a.groupby("asset").indices.values():
        idx = sorted(idx)
        for pos, j in enumerate(idx):
            if stage[j] <= 1:
                continue
            for i in reversed(idx[:pos]):
                if ts[j] - ts[i] > ASSET_CHAIN_GAP:
                    break
                if 0 < stage[i] < stage[j]:
                    uf.union(i, j)
                    links.append((i, "asset_chain_30m"))
                    break

    comps, rules = defaultdict(list), defaultdict(set)
    for i in range(len(a)):
        comps[uf.find(i)].append(i)
    for i, rule in links:
        rules[uf.find(i)].add(rule)

    incidents = [_build_incident(a.iloc[m].sort_values("timestamp"), rules[r]) for r, m in comps.items()]
    incidents.sort(key=lambda x: x["start"])
    for k, inc in enumerate(incidents, 1):
        inc["incident_id"] = f"INC-{k:04d}"
        for f_i, f in enumerate(inc["findings"], 1):
            f["finding_id"] = f"INC-{k:04d}-F{f_i}"
    return incidents


def _build_incident(g: pd.DataFrame, rules: set) -> dict:
    order = list(dict.fromkeys(g["finding_type"]))          # stages by first appearance
    real_stages = [s for s in order if s != "anomalous_activity"]
    base = max(SEV_RANK[s] for s in g["alert_severity"])
    boosted = len(real_stages) >= 2 and base < 4
    sev = SEV_LEVELS[min(base + (1 if boosted else 0), 4) - 1]
    sev_reason = (f"max alert severity '{SEV_LEVELS[base - 1]}' raised one level because "
                  f"{len(real_stages)} distinct stages were observed ({' -> '.join(real_stages)})"
                  if boosted else f"max alert severity '{SEV_LEVELS[base - 1]}'"
                  + (" (single stage)" if len(real_stages) <= 1 else
                     f" (multi-stage: {' -> '.join(real_stages)}; already at maximum level)"))

    # timeline = runs of consecutive alerts with the same finding type
    g_tl = g[g["finding_type"] != "anomalous_activity"] if real_stages else g
    n_unclassified = int(len(g) - len(g_tl))
    timeline, run = [], []
    for _, row in g_tl.iterrows():
        if run and row["finding_type"] != run[-1]["finding_type"]:
            timeline.append(run); run = []
        run.append(row)
    timeline.append(run)
    tl = []
    for r in timeline:
        seg = pd.DataFrame(r)
        tl.append({"start": _t(seg.timestamp.min()), "end": _t(seg.timestamp.max()),
                   "stage": seg.finding_type.iloc[0], "alert_count": len(seg),
                   "detail": describe(seg.finding_type.iloc[0], seg)})

    findings = []
    for ft in order:
        gg = g[g.finding_type == ft]
        findings.append({
            "finding_type": ft, "alert_count": int(len(gg)),
            "max_alert_severity": gg.alert_severity.iloc[0],
            "first_seen": _t(gg.timestamp.min()), "last_seen": _t(gg.timestamp.max()),
            "source_ips": sorted(gg.source_ip.unique().tolist()),
            "assets": sorted(gg.asset.unique().tolist()),
            "users": sorted(gg.user.unique().tolist()),
            "evidence": [describe(ft, gg),
                         f"first alert {_t(gg.timestamp.min())}, last alert {_t(gg.timestamp.max())}",
                         f"mean model score {gg.model_score.mean():.2f}; example reason: {gg.reason.iloc[0]}"],
            "sample_event_ids": [int(x) for x in gg.event_id.head(10)],
        })

    shown = tl[:6]
    explanation = "; then ".join(f"[{t['start'][11:19]}] {t['detail']}" for t in shown)
    if len(tl) > 6:
        explanation += f"; ... (+{len(tl) - 6} more timeline segments)"
    if n_unclassified:
        explanation += f". Also {n_unclassified} related alert(s) flagged by the model but not matching a specific rule"
    return {
        "start": _t(g.timestamp.min()), "end": _t(g.timestamp.max()),
        "duration_seconds": int((g.timestamp.max() - g.timestamp.min()).total_seconds()),
        "alert_count": int(len(g)),
        "source_ips": sorted(g.source_ip.unique().tolist()),
        "affected_assets": sorted(g.asset.unique().tolist()),
        "users": sorted(g.user.unique().tolist()),
        "stages": order, "severity": sev, "severity_reason": sev_reason,
        "correlation_rules": sorted(rules) if rules else ["single_alert_group"],
        "unclassified_alerts": n_unclassified,
        "timeline": tl, "explanation": explanation, "findings": findings,
    }
