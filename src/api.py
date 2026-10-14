"""
Task 4: FastAPI backend.

  GET  /health            service + model + connector status
  POST /analyze           JSON body {"logs": [...], "enrich": true}
  POST /analyze/upload    multipart file upload (.csv / .json)
  GET  /report/{id}       generated report (?format=html|json)

Run: uvicorn src.api:app --reload      (interactive docs at /docs)
"""
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Path as PathParam, Query, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from src.compliance import load_mapping
from src.connectors import ConnectorError, ThreatIntel, parse_log_bytes
from src.detect import load_model
from src.report import render_report
from src.run_pipeline import _default, analyze
from src.schemas import AnalyzeRequest, events_to_dataframe, validate_dataframe

logger = logging.getLogger("api")
REPORT_DIR = Path("reports/generated")
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_MB", "10")) * 1024 * 1024
state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        state["bundle"] = load_model()
    except FileNotFoundError:
        state["bundle"] = None
        logger.error("models/model.joblib not found - run `python -m src.train`")
    state["mapping"] = load_mapping()
    state["intel"] = ThreatIntel()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title="Security Log Analysis API", version="1.0.0", lifespan=lifespan)


class AnalyzeResponse(BaseModel):
    report_id: str
    report_url: str
    summary: dict
    threat_intel: dict
    incidents: list[dict]
    compliance_findings: list[dict]


def _run(df, enrich: bool, input_name: str) -> dict:
    if state.get("bundle") is None:
        raise HTTPException(503, "Detection model not available. Train it first: python -m src.train")
    try:
        res = analyze(df, bundle=state["bundle"], mapping=state["mapping"],
                      enricher=state["intel"] if enrich else None)
    except Exception:
        logger.exception("analysis failed")
        raise HTTPException(500, "Analysis failed. See server logs for details.")

    incidents, findings = res["incidents"], res["findings"]
    report_id = uuid.uuid4().hex[:12]
    sev = {}
    for i in incidents:
        sev[i["severity"]] = sev.get(i["severity"], 0) + 1
    summary = {"events_analyzed": int(len(res["scored"])), "alerts": int(len(res["alerts"])),
               "incidents": len(incidents), "compliance_findings": len(findings),
               "incidents_by_severity": sev}
    meta = {"report_id": report_id, "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "input_name": input_name, "n_events": summary["events_analyzed"],
            "n_alerts": summary["alerts"], "intel": res["intel_meta"]}
    payload = {"report_id": report_id, "report_url": f"/report/{report_id}", "summary": summary,
               "threat_intel": res["intel_meta"], "incidents": incidents, "compliance_findings": findings}
    payload = json.loads(json.dumps(payload, default=_default))   # make numpy types JSON-safe
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / f"{report_id}.json").write_text(json.dumps(payload))
    (REPORT_DIR / f"{report_id}.html").write_text(render_report(payload["incidents"], payload["compliance_findings"], meta))
    return payload


@app.get("/health")
def health():
    return {"status": "ok" if state.get("bundle") is not None else "degraded",
            "model_loaded": state.get("bundle") is not None,
            "threat_intel": state["intel"].status(),
            "version": app.version}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_json(req: AnalyzeRequest):
    return _run(events_to_dataframe(req.logs), req.enrich, "JSON request body")


@app.post("/analyze/upload", response_model=AnalyzeResponse)
async def analyze_upload(file: UploadFile = File(...), enrich: bool = Query(True)):
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File too large (limit {MAX_UPLOAD_BYTES // 1024 // 1024} MB)")
    try:
        df = validate_dataframe(parse_log_bytes(content, file.filename or ""))
    except ConnectorError as e:
        raise HTTPException(415 if "Unsupported" in str(e) else 400, str(e))
    except ValueError as e:
        raise HTTPException(422, str(e))
    return await run_in_threadpool(_run, df, enrich, Path(file.filename).name)


@app.get("/report/{report_id}")
def get_report(report_id: str = PathParam(..., pattern=r"^[a-f0-9]{12}$"),
               format: str = Query("html", pattern="^(html|json)$")):
    path = REPORT_DIR / f"{report_id}.{format}"
    if not path.exists():
        raise HTTPException(404, "Report not found")
    if format == "json":
        return JSONResponse(json.loads(path.read_text()))
    return HTMLResponse(path.read_text())
