"""Sentinel API: authenticated IOC extraction, enrichment and SQLite cache."""
from __future__ import annotations

import hmac
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from .database import connect, init_db, record_activity
from .enrichment import aggregate, enrich_one, provider_status, PROVIDER_FRESHNESS
from .extraction import extract_indicators
from .risk_rules import assess_evidence

APP_NAME = "Sentinel Threat Intelligence API"
ADMIN_USERNAME = os.getenv("SENTINEL_ADMIN_USERNAME", "admin").strip() or "admin"
MAX_ALERT_CHARS = int(os.getenv("MAX_ALERT_CHARS", "200000"))


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title=APP_NAME, version="1.0.0", docs_url="/api/docs", redoc_url=None, lifespan=lifespan)
origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["Content-Type", "X-Admin-Username"])
_requests: dict[str, deque[float]] = defaultdict(deque)


class ExtractRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_ALERT_CHARS)


class EnrichRequest(BaseModel):
    alert_id: str = Field(min_length=1)
    indicators: list[int] = Field(min_length=1, max_length=100)


def authenticate(x_admin_username: str | None = Header(default=None, alias="X-Admin-Username")) -> None:
    if not x_admin_username or not hmac.compare_digest(x_admin_username.strip(), ADMIN_USERNAME):
        raise HTTPException(status_code=401, detail="Admin username required")


@app.middleware("http")
async def basic_rate_limit(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.url.path not in {"/api/healthz"}:
        bucket = _requests[request.client.host if request.client else "unknown"]
        now = time.monotonic()
        while bucket and bucket[0] < now - 60: bucket.popleft()
        if len(bucket) >= 120:
            from fastapi.responses import JSONResponse
            try: record_activity("error", "API request rate limit reached", {"path": request.url.path})
            except Exception: pass
            return JSONResponse({"detail": "Rate limit exceeded; retry in a minute."}, status_code=429, headers={"Retry-After": "60"})
        bucket.append(now)
    try:
        response = await call_next(request)
    except Exception as exc:
        if request.url.path.startswith("/api/"):
            try: record_activity("error", "API request failed", {"path": request.url.path, "error": type(exc).__name__})
            except Exception: pass
        raise
    if response.status_code >= 400 and request.url.path.startswith("/api/"):
        try: record_activity("error", "API request returned an error", {"path": request.url.path, "status": response.status_code})
        except Exception: pass
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/api/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/health", dependencies=[Depends(authenticate)])
def health() -> dict[str, Any]:
    try:
        with connect() as db: db.execute("SELECT 1").fetchone()
        db_status = "connected"
    except Exception:
        db_status = "disconnected"
    return {"status": "connected" if db_status == "connected" else "degraded", "backend": "connected", "database": db_status, "providers": provider_status()}


@app.get("/api/session", dependencies=[Depends(authenticate)])
def session_status() -> dict[str, bool]:
    return {"authenticated": True}


@app.post("/api/extract", dependencies=[Depends(authenticate)])
def extract(payload: ExtractRequest) -> dict[str, Any]:
    indicators = extract_indicators(payload.text)
    alert_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        db.execute("INSERT INTO alerts(id,raw_text,created_at) VALUES(?,?,?)", (alert_id, payload.text, now))
        saved = []
        for item in indicators:
            db.execute("INSERT INTO indicators(value,type,first_seen,last_seen,verdict,risk_score,alert_id) VALUES(?,?,?,?,?,?,?) ON CONFLICT(value,type) DO UPDATE SET last_seen=excluded.last_seen,alert_id=excluded.alert_id",
                       (item["value"], item["type"], now, now, "unknown", None, alert_id))
            row = db.execute("SELECT id,value,type,first_seen,last_seen,verdict,risk_score,alert_id FROM indicators WHERE value=? AND type=?", (item["value"], item["type"])).fetchone()
            saved.append(dict(row))
        db.execute("INSERT INTO activity_log(action,message,details,created_at) VALUES(?,?,?,?)",
                   ("extraction", f"Extracted {len(saved)} indicator(s)", json.dumps({"alert_id": alert_id, "count": len(saved)}), now))
    return {"alert_id": alert_id, "created_at": now, "count": len(saved), "indicators": saved}


async def _process_enrichment_job(job_id: str, alert_id: str, indicator_ids: list[int]) -> None:
    with connect() as db:
        db.execute("UPDATE enrichment_jobs SET status='running' WHERE id=?", (job_id,))
    warnings: list[str] = []
    try:
        for completed, indicator_id in enumerate(indicator_ids, start=1):
            with connect() as db:
                row = db.execute("SELECT id,value,type FROM indicators WHERE id=? AND alert_id=?", (indicator_id, alert_id)).fetchone()
            if row is None:
                warnings.append(f"Indicator {indicator_id} is no longer linked to this alert")
            else:
                results = await enrich_one(row["id"], row["type"], row["value"])
                verdict, score = aggregate(results)
                with connect() as db:
                    db.execute("UPDATE indicators SET verdict=?,risk_score=? WHERE id=?", (verdict, score, row["id"]))
                for provider_result in results:
                    failed = provider_result.get("status") == "error"
                    if failed:
                        warnings.append(f"{provider_result['provider']}: {provider_result.get('metadata', {}).get('error', 'lookup failed')}")
                    record_activity("error" if failed else "enrichment", f"{provider_result['provider']} lookup {'failed' if failed else 'completed'}",
                                    {"indicator_id": row["id"], "provider": provider_result["provider"], "status": provider_result.get("status")})
            with connect() as db:
                db.execute("UPDATE enrichment_jobs SET completed=?,warnings=? WHERE id=?", (completed, json.dumps(warnings), job_id))
        with connect() as db:
            db.execute("UPDATE enrichment_jobs SET status='completed',finished_at=? WHERE id=?",
                       (datetime.now(timezone.utc).isoformat(), job_id))
        record_activity("enrichment", f"Enrichment job completed for {len(indicator_ids)} indicator(s)",
                        {"alert_id": alert_id, "job_id": job_id, "count": len(indicator_ids)})
    except Exception as exc:
        warnings.append(f"Enrichment job failed: {type(exc).__name__}")
        with connect() as db:
            db.execute("UPDATE enrichment_jobs SET status='failed',warnings=?,finished_at=? WHERE id=?",
                       (json.dumps(warnings), datetime.now(timezone.utc).isoformat(), job_id))
        record_activity("error", "Enrichment job failed", {"alert_id": alert_id, "job_id": job_id, "error": type(exc).__name__})


@app.post("/api/enrich", status_code=202, dependencies=[Depends(authenticate)])
def enrich(payload: EnrichRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    indicator_ids = list(dict.fromkeys(payload.indicators))
    with connect() as db:
        if not db.execute("SELECT 1 FROM alerts WHERE id=?", (payload.alert_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Source alert not found")
        for indicator_id in indicator_ids:
            row = db.execute("SELECT alert_id FROM indicators WHERE id=?", (indicator_id,)).fetchone()
            if row is None: raise HTTPException(status_code=404, detail=f"Indicator {indicator_id} not found")
            if row["alert_id"] != payload.alert_id:
                raise HTTPException(status_code=400, detail=f"Indicator {indicator_id} does not belong to this alert")
        job_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        db.execute("INSERT INTO enrichment_jobs(id,alert_id,status,total,completed,warnings,created_at) VALUES(?,?, 'pending', ?, 0, '[]', ?)",
                   (job_id, payload.alert_id, len(indicator_ids), now))
    background_tasks.add_task(_process_enrichment_job, job_id, payload.alert_id, indicator_ids)
    return {"job_id": job_id, "alert_id": payload.alert_id, "status": "pending", "total": len(indicator_ids)}


@app.get("/api/jobs/{job_id}", dependencies=[Depends(authenticate)])
def enrichment_job(job_id: str) -> dict[str, Any]:
    with connect() as db:
        row = db.execute("SELECT id,alert_id,status,total,completed,warnings,created_at,finished_at FROM enrichment_jobs WHERE id=?", (job_id,)).fetchone()
    if not row: raise HTTPException(status_code=404, detail="Enrichment job not found")
    result = dict(row)
    result["job_id"] = result.pop("id")
    result["warnings"] = json.loads(result["warnings"])
    return result


def _indicator_query(where: str = "", params: tuple[Any, ...] = (), limit: int = 50, offset: int = 0, sort_by: str = "last_seen") -> tuple[list[dict[str, Any]], int]:
    ordering = {"last_seen": "last_seen DESC", "risk_score": "risk_score DESC, last_seen DESC", "value": "value COLLATE NOCASE ASC"}.get(sort_by, "last_seen DESC")
    with connect() as db:
        total = db.execute(f"SELECT COUNT(*) FROM indicators {where}", params).fetchone()[0]
        rows = db.execute(f"SELECT * FROM indicators {where} ORDER BY {ordering} LIMIT ? OFFSET ?", (*params, limit, offset)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            enriched = db.execute("SELECT provider,verdict,risk_score,metadata,status,checked_at FROM enrichment_results WHERE indicator_id=? ORDER BY id DESC", (row["id"],)).fetchall()
            seen = set(); providers = []
            for entry in enriched:
                if entry["provider"] not in seen:
                    seen.add(entry["provider"]); providers.append({"provider": entry["provider"], "verdict": entry["verdict"], "risk_score": entry["risk_score"], "metadata": json.loads(entry["metadata"]), "status": entry["status"], "checked_at": entry["checked_at"]})
            item["providers"] = providers
            item["assessment"] = assess_evidence(providers)
            now = datetime.now(timezone.utc)
            freshness = []
            for result in providers:
                if result.get("status") == "error" or not result.get("checked_at"):
                    continue
                checked = datetime.fromisoformat(result["checked_at"].replace("Z", "+00:00"))
                if checked.tzinfo is None:
                    checked = checked.replace(tzinfo=timezone.utc)
                age = now - checked
                freshness.append({"provider": result["provider"], "checked_at": result["checked_at"], "fresh": age <= PROVIDER_FRESHNESS.get(result["provider"], timedelta(days=7))})
            item["knowledge_cache"] = {"state": "fresh" if any(source["fresh"] for source in freshness) else "stale" if freshness else "unseen", "sources": freshness}
            result.append(item)
    return result, total


@app.get("/api/indicators", dependencies=[Depends(authenticate)])
def indicators(page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100), search: str = "", type: str = "", verdict: str = "", sort_by: str = Query("last_seen", pattern="^(last_seen|risk_score|value)$")) -> dict[str, Any]:
    clauses, params = [], []
    if search: clauses.append("(value LIKE ? OR type LIKE ?)"); params.extend([f"%{search}%", f"%{search}%"])
    if type: clauses.append("type=?"); params.append(type)
    if verdict: clauses.append("verdict=?"); params.append(verdict)
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    items, total = _indicator_query(where, tuple(params), page_size, (page - 1) * page_size, sort_by)
    return {"items": items, "page": page, "page_size": page_size, "total": total, "pages": (total + page_size - 1) // page_size}


@app.get("/api/indicators/{indicator_id}", dependencies=[Depends(authenticate)])
def indicator_detail(indicator_id: int) -> dict[str, Any]:
    items, _ = _indicator_query("WHERE id=?", (indicator_id,), 1, 0)
    if not items: raise HTTPException(status_code=404, detail="Indicator not found")
    item = items[0]
    with connect() as db:
        alert = db.execute("SELECT id,raw_text,created_at FROM alerts WHERE id=?", (item["alert_id"],)).fetchone() if item.get("alert_id") else None
        related = db.execute("SELECT id,value,type,verdict,risk_score FROM indicators WHERE alert_id=? AND id<>? LIMIT 20", (item.get("alert_id"), indicator_id)).fetchall() if item.get("alert_id") else []
    item["source_alert"] = dict(alert) if alert else None
    item["related"] = [dict(row) for row in related]
    return item


@app.get("/api/activity", dependencies=[Depends(authenticate)])
def activity(page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)) -> dict[str, Any]:
    with connect() as db:
        total = db.execute("SELECT COUNT(*) FROM activity_log").fetchone()[0]
        rows = db.execute("SELECT * FROM activity_log ORDER BY created_at DESC LIMIT ? OFFSET ?", (page_size, (page - 1) * page_size)).fetchall()
    return {"items": [{**dict(row), "details": json.loads(row["details"])} for row in rows], "page": page, "page_size": page_size, "total": total, "pages": (total + page_size - 1) // page_size}


@app.get("/api/summary", dependencies=[Depends(authenticate)])
def summary() -> dict[str, Any]:
    with connect() as db:
        total = db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
        malicious = db.execute("SELECT COUNT(*) FROM indicators WHERE verdict='malicious' AND last_seen>=datetime('now','-7 days')").fetchone()[0]
        types = [dict(row) for row in db.execute("SELECT type,COUNT(*) AS count FROM indicators GROUP BY type ORDER BY count DESC LIMIT 6")]
        trend_rows = db.execute("SELECT substr(last_seen,1,10) AS date, COUNT(*) AS count FROM indicators WHERE last_seen>=datetime('now','-6 days') GROUP BY date ORDER BY date").fetchall()
        unknown = db.execute("SELECT COUNT(*) FROM indicators WHERE verdict='unknown'").fetchone()[0]
    counts_by_date = {row["date"]: row["count"] for row in trend_rows}
    today = datetime.now(timezone.utc).date()
    trend = [{"date": (today - timedelta(days=age)).isoformat(), "count": counts_by_date.get((today - timedelta(days=age)).isoformat(), 0)} for age in range(6, -1, -1)]
    return {"total_indicators": total, "malicious_this_week": malicious, "unknown_indicators": unknown, "top_types": types, "trend": trend}
