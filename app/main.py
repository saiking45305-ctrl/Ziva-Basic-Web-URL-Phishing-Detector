"""Ziva - Basic Web URL Phishing Detector FastAPI backend."""

from collections import defaultdict
import logging
from pathlib import Path
import time
from typing import Dict, List

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.analyzer import analyze_url
from app.schemas import AnalyzeRequest, AnalyzeResponse, FindingSchema, HealthResponse, ParsedURLSchema

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] Ziva: %(message)s")
logger = logging.getLogger("ziva")

app = FastAPI(
    title="Ziva",
    description="Static URL Phishing Detector",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_request_history: Dict[str, List[float]] = defaultdict(list)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path == "/api/analyze" and request.method == "POST":
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        _request_history[client_ip] = [t for t in _request_history[client_ip] if t > now - 60]
        if len(_request_history[client_ip]) >= 30:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Maximum 30 analysis requests per minute allowed."}
            )
        _request_history[client_ip].append(now)
    return await call_next(request)

@app.get("/api/health", response_model=HealthResponse)
def health_check():
    return HealthResponse(status="ok", app="Ziva", tagline="Check before you click.", version="1.0.0")

@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(payload: AnalyzeRequest, request: Request):
    try:
        result = analyze_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return AnalyzeResponse(
        url=result.url,
        normalized_url=result.normalized_url,
        defanged_url=result.defanged_url,
        score=result.score,
        verdict=result.verdict,  # type: ignore
        findings=[
            FindingSchema(rule_id=f.rule_id, title=f.title, severity=f.severity, explanation=f.explanation)  # type: ignore
            for f in result.findings
        ],
        parsed=ParsedURLSchema(
            scheme=result.parsed.scheme,
            hostname=result.parsed.hostname,
            registered_domain=result.parsed.registered_domain,
            subdomains=result.parsed.subdomains,
            path=result.parsed.path,
            port=result.parsed.port,
        ),
    )

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/", include_in_schema=False)
def serve_index():
    return FileResponse(str(STATIC_DIR / "index.html"))
