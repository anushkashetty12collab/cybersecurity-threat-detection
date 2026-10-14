"""Task 5: render the security report (HTML) from an analysis result. Jinja2 autoescape is ON,
because usernames/assets come from untrusted logs."""
import json
from collections import defaultdict
from pathlib import Path

from jinja2 import Environment, select_autoescape

TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Analysis Report {{ meta.report_id }}</title>
<style>
:root{--bg:#fff;--fg:#1a1f2b;--muted:#5b6475;--card:#f5f7fa;--line:#dde2ea;--crit:#b3261e;--high:#d9622b;--med:#b8860b;--low:#2e7d32}
@media (prefers-color-scheme:dark){:root{--bg:#14171d;--fg:#e8ebf0;--muted:#9aa4b5;--card:#1e232c;--line:#323a47}}
body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--fg);max-width:1100px;margin:0 auto;padding:24px;line-height:1.5}
h1{margin-bottom:0} h2{border-bottom:2px solid var(--line);padding-bottom:4px;margin-top:36px} .muted{color:var(--muted);font-size:.9em}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;min-width:130px}
.card b{display:block;font-size:1.6em}
table{border-collapse:collapse;width:100%;font-size:.9em;margin:8px 0} th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top} th{background:var(--card)}
.wrap{overflow-x:auto}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:.8em;font-weight:600}
.sev-critical{background:var(--crit)}.sev-high{background:var(--high)}.sev-medium{background:var(--med)}.sev-low{background:var(--low)}
.incident{border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:18px 0}
.finding{background:var(--card);border-radius:6px;padding:8px 12px;margin:10px 0}
code{background:var(--card);padding:0 4px;border-radius:3px}
</style></head><body>
<h1>Security Analysis Report</h1>
<p class="muted">Report {{ meta.report_id }} &middot; generated {{ meta.generated_at }} &middot; source: {{ meta.input_name }}</p>

<div class="cards">
 <div class="card"><b>{{ meta.n_events }}</b>events analysed</div>
 <div class="card"><b>{{ meta.n_alerts }}</b>alerts</div>
 <div class="card"><b>{{ incidents|length }}</b>incidents</div>
 <div class="card"><b>{{ findings|length }}</b>compliance findings</div>
 <div class="card"><b>{{ meta.intel.mode }}</b>threat-intel mode</div>
</div>

<h2>1. Executive summary</h2>
<p>Incidents by severity:
{% for lvl in ['critical','high','medium','low'] %}{% if sev_counts.get(lvl) %}<span class="badge sev-{{ lvl }}">{{ lvl }}: {{ sev_counts[lvl] }}</span> {% endif %}{% endfor %}</p>
{% if meta.intel.mode == 'offline_fallback' %}<p class="muted">Threat-intel API unavailable or not configured: enrichment used the local SAMPLE blocklist (demo data, not real intelligence).</p>{% endif %}
{% if incidents %}
<div class="wrap"><table><tr><th>Incident</th><th>Severity</th><th>Start</th><th>Assets</th><th>Source IPs</th><th>Stages</th><th>Alerts</th></tr>
{% for i in incidents %}<tr><td><a href="#{{ i.incident_id }}">{{ i.incident_id }}</a></td>
<td><span class="badge sev-{{ i.severity }}">{{ i.severity }}</span></td><td>{{ i.start }}</td>
<td>{{ i.affected_assets|join(', ') }}</td><td>{{ i.source_ips[:3]|join(', ') }}{% if i.source_ips|length > 3 %} +{{ i.source_ips|length - 3 }}{% endif %}</td>
<td>{{ i.stages|join(' &rarr; ') }}</td><td>{{ i.alert_count }}</td></tr>{% endfor %}</table></div>
{% else %}<p>No incidents were detected in the analysed events.</p>{% endif %}

<h2>2. Detection model</h2>
{% if metrics %}
<p>Best supervised model: <b>{{ metrics.best_model }}</b> (time-based train/test split, synthetic data).</p>
<div class="wrap"><table><tr><th>Model</th><th>Precision</th><th>Recall</th><th>F1</th><th>PR-AUC</th><th>FP</th><th>FN</th></tr>
{% for r in metrics.results %}<tr><td>{{ r.model }}</td><td>{{ r.precision }}</td><td>{{ r.recall }}</td><td>{{ r.f1 }}</td><td>{{ r.pr_auc }}</td>
<td>{{ r.confusion_matrix.fp }}</td><td>{{ r.confusion_matrix.fn }}</td></tr>{% endfor %}</table></div>
{% else %}<p class="muted">metrics.json not found.</p>{% endif %}

<h2>3. Incident details</h2>
{% for i in incidents %}
<div class="incident" id="{{ i.incident_id }}">
<h3>{{ i.incident_id }} <span class="badge sev-{{ i.severity }}">{{ i.severity }}</span></h3>
<p class="muted">{{ i.start }} &rarr; {{ i.end }} ({{ i.duration_seconds }}s) &middot; correlation: {{ i.correlation_rules|join(', ') }}</p>
<p><b>Severity reasoning:</b> {{ i.severity_reason }}</p>
<p><b>Explanation:</b> {{ i.explanation }}</p>
<p><b>Affected assets:</b> {{ i.affected_assets|join(', ') }} &middot; <b>Accounts:</b> {{ i.users[:5]|join(', ') }}</p>
<h4>Timeline</h4>
<div class="wrap"><table><tr><th>Start</th><th>End</th><th>Stage</th><th>Alerts</th><th>Detail</th></tr>
{% for t in i.timeline %}<tr><td>{{ t.start }}</td><td>{{ t.end }}</td><td>{{ t.stage }}</td><td>{{ t.alert_count }}</td><td>{{ t.detail }}</td></tr>{% endfor %}</table></div>
{% if i.threat_intel %}<h4>Threat intelligence</h4>
<div class="wrap"><table><tr><th>IP</th><th>Source</th><th>Score</th><th>Country</th><th>Notes</th></tr>
{% for t in i.threat_intel %}<tr><td>{{ t.ip }}</td><td>{{ t.source }}</td><td>{{ t.abuse_score if t.abuse_score is not none else 'n/a' }}</td>
<td>{{ t.country or '' }}</td><td>{{ t.categories|join(', ') }}{% if t.status in ('unavailable','skipped_limit') %}{{ t.status }}{% endif %}</td></tr>{% endfor %}</table></div>{% endif %}
<h4>Findings, compliance mapping and remediation</h4>
{% for f in by_incident[i.incident_id] %}
<div class="finding">
<b>{{ f.finding_id }} &mdash; {{ f.title }}</b> <span class="badge sev-{{ f.risk_level|lower }}">{{ f.risk_level }}</span>
<p class="muted">{{ f.risk_rationale }}</p>
<p><b>{{ f.framework }}:</b> {% for c in f.controls %}<code>{{ c.id }}</code> {{ c.title }}{% if not loop.last %}; {% endif %}{% endfor %}</p>
<p><b>ISO/IEC 27001:2022:</b> {% for c in f.iso_27001_2022 %}<code>{{ c.id }}</code> {{ c.title }}{% if not loop.last %}; {% endif %}{% endfor %}</p>
<b>Evidence</b><ul>{% for e in f.evidence %}<li>{{ e }}</li>{% endfor %}<li>Sample event IDs: {{ f.sample_event_ids|join(', ') }}</li></ul>
<b>Recommended remediation</b><ul>{% for r in f.remediation %}<li>{{ r }}</li>{% endfor %}</ul>
</div>{% endfor %}
</div>
{% endfor %}

<h2>4. Limitations</h2>
<ul>
<li>The model is trained on synthetic data; real-world accuracy is unknown. Metrics reflect the synthetic test window only.</li>
<li>Alert types come from transparent rules applied to model-flagged events; legitimate periodic traffic (monitoring agents) can look like C2 beaconing.</li>
<li>Correlation rules can merge unrelated activity on the same asset within 30 minutes.</li>
<li>Control mappings are a static lookup table and should be reviewed by a security professional.</li>
</ul>
</body></html>"""

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
_template = _env.from_string(TEMPLATE)


def load_metrics(path: str = "models/metrics.json"):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def render_report(incidents: list[dict], findings: list[dict], meta: dict) -> str:
    by_incident = defaultdict(list)
    for f in findings:
        by_incident[f["incident_id"]].append(f)
    sev_counts = defaultdict(int)
    for i in incidents:
        sev_counts[i["severity"]] += 1
    return _template.render(incidents=incidents, findings=findings, by_incident=by_incident,
                            sev_counts=dict(sev_counts), meta=meta, metrics=load_metrics())
