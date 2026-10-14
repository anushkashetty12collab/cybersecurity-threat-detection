"""
Task 4: data connectors.

1. File connector      - CSV / JSON log files (local path or uploaded bytes)
2. Threat-intel connector - AbuseIPDB v2 "check" endpoint, key read from the environment (.env, never committed).
   If the key is missing, the API errors, times out or is rate-limited, the connector falls back to a small
   LOCAL SAMPLE blocklist (clearly labelled as sample data) and the pipeline keeps working.
"""
import io
import ipaddress
import json
import logging
import os
import time
from pathlib import Path

import pandas as pd
import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("connectors")

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
SAMPLE_LIST = Path("data/threat_intel/sample_blocklist.json")
HIGH_ABUSE_SCORE = 75
_INTERNAL = [ipaddress.ip_network(n) for n in
             ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
              "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"]]


class ConnectorError(ValueError):
    pass


# ----------------------------------------------------------- file connector --
def parse_log_bytes(content: bytes, filename: str) -> pd.DataFrame:
    name = filename.lower()
    try:
        if name.endswith(".csv"):
            return pd.read_csv(io.BytesIO(content))
        if name.endswith(".json"):
            data = json.loads(content.decode("utf-8"))
            if isinstance(data, dict):
                data = data.get("logs", [])
            if not isinstance(data, list):
                raise ConnectorError("JSON must be a list of events or {\"logs\": [...]}")
            return pd.DataFrame(data)
    except ConnectorError:
        raise
    except Exception as e:
        raise ConnectorError(f"Could not parse '{filename}': {type(e).__name__}") from e
    raise ConnectorError("Unsupported file type: use .csv or .json")


def load_logs_from_file(path: str) -> pd.DataFrame:
    p = Path(path)
    if not p.exists():
        raise ConnectorError(f"File not found: {path}")
    return parse_log_bytes(p.read_bytes(), p.name)


# ------------------------------------------------------ threat intelligence --
def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # never send malformed values to a third party
    return any(addr in net for net in _INTERNAL)


class ThreatIntel:
    def __init__(self, api_key: str | None = None, timeout: float = 5.0,
                 max_lookups: int = 20, session=None):
        self.api_key = api_key if api_key is not None else os.getenv("ABUSEIPDB_API_KEY", "")
        self.timeout, self.max_lookups = timeout, max_lookups
        self.session = session or requests
        self._cache: dict[str, dict] = {}
        self._down_until = 0.0
        try:
            raw = json.loads(SAMPLE_LIST.read_text())
            self._sample = {k: v for k, v in raw.items() if not k.startswith("_")}
        except (OSError, ValueError):
            self._sample = {}

    def status(self) -> dict:  # safe for /health: never exposes the key
        return {"provider": "AbuseIPDB", "api_key_configured": bool(self.api_key),
                "fallback": "local_sample_blocklist"}

    def lookup(self, ip: str) -> dict:
        if ip in self._cache:
            return self._cache[ip]
        if self.api_key and time.time() >= self._down_until:
            try:
                r = self.session.get(ABUSE_URL,
                                     headers={"Key": self.api_key, "Accept": "application/json"},
                                     params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=self.timeout)
                if r.status_code == 429:
                    raise requests.RequestException("rate limited")
                r.raise_for_status()
                d = r.json()["data"]
                res = {"ip": ip, "source": "abuseipdb", "status": "ok",
                       "abuse_score": int(d["abuseConfidenceScore"]),
                       "country": d.get("countryCode"), "isp": d.get("isp"),
                       "total_reports": d.get("totalReports"), "categories": []}
                self._cache[ip] = res
                return res
            except (requests.RequestException, ValueError, KeyError, TypeError) as e:
                self._down_until = time.time() + 60          # simple circuit breaker
                logger.warning("AbuseIPDB unavailable (%s); using offline fallback", type(e).__name__)
        return self._fallback(ip)

    def _fallback(self, ip: str) -> dict:
        hit = self._sample.get(ip)
        if hit:
            return {"ip": ip, "source": "local_sample_blocklist", "status": "fallback",
                    "abuse_score": hit["score"], "country": None, "isp": None,
                    "total_reports": None, "categories": hit.get("categories", [])}
        return {"ip": ip, "source": "none", "status": "unavailable", "abuse_score": None,
                "country": None, "isp": None, "total_reports": None, "categories": []}

    def enrich(self, ips) -> dict[str, dict]:
        external = sorted({ip for ip in ips if not is_internal(ip)})
        out = {}
        for n, ip in enumerate(external):
            if n >= self.max_lookups:   # protect the free-tier quota
                out[ip] = {"ip": ip, "source": "none", "status": "skipped_limit", "abuse_score": None,
                           "country": None, "isp": None, "total_reports": None, "categories": []}
            else:
                out[ip] = self.lookup(ip)
        return out

    @staticmethod
    def mode(results: dict) -> str:
        if not results:
            return "no_external_ips"
        return "live" if any(r["status"] == "ok" for r in results.values()) else "offline_fallback"


def _intel_line(r: dict) -> str:
    if r["source"] == "abuseipdb":
        extra = f", {r['total_reports']} reports" if r.get("total_reports") is not None else ""
        cc = f", country {r['country']}" if r.get("country") else ""
        return f"Threat intel (AbuseIPDB): {r['ip']} abuse confidence {r['abuse_score']}%{extra}{cc}"
    cats = ", ".join(r.get("categories", []))
    return (f"Threat intel (local SAMPLE blocklist, not live data): {r['ip']} listed "
            f"with score {r['abuse_score']} ({cats})")


def attach_intel(incidents: list[dict], ti: ThreatIntel, high: int = HIGH_ABUSE_SCORE) -> dict:
    """Add threat-intel results to incidents and append evidence lines to affected findings."""
    all_ips = set()
    for inc in incidents:
        all_ips.update(inc["source_ips"])
        for f in inc["findings"]:
            all_ips.update(f.get("dest_ips", []))
    results = ti.enrich(all_ips)
    for inc in incidents:
        inc_ips = set(inc["source_ips"]) | {d for f in inc["findings"] for d in f.get("dest_ips", [])}
        inc["threat_intel"] = [results[i] for i in sorted(inc_ips) if i in results]
        for f in inc["findings"]:
            for ip in sorted(set(f["source_ips"]) | set(f.get("dest_ips", []))):
                r = results.get(ip)
                if r and r["abuse_score"] is not None and r["abuse_score"] >= high:
                    f["evidence"].append(_intel_line(r))
    return {"provider": "AbuseIPDB", "mode": ti.mode(results), "ips_checked": len(results)}
