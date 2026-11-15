import logging
import os
import time
import warnings
from collections import defaultdict
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

# Suppress urllib3 LibreSSL warning on macOS
warnings.filterwarnings("ignore", category=Warning)

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.models.requests import AnalyzeRequest
from app.models.responses import AnalyzeResponse, HealthResponse
from app.engine.coordinator import process_analysis


app = FastAPI(
    title="Inspectra — Suspicious Content Analyzer API",
    description="Explainable cybersecurity analysis engine for phishing, digital-arrest scams, and malicious app requests.",
    version=settings.ENGINE_VERSION,
    docs_url="/docs",
    redoc_url=None,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_origin_regex=r"https?://.*",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# Standard security headers applied to all responses
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


def apply_security_headers(response: Response) -> Response:
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


# In-memory sliding window rate limiter
# Maps client IP to list of timestamps
_rate_limit_records: Dict[str, list[float]] = defaultdict(list)
_request_counter: int = 0


@app.middleware("http")
async def rate_limit_and_security_headers_middleware(request: Request, call_next):
    global _request_counter
    path = request.url.path

    # Only apply rate limiting to /api/ endpoints, excluding /api/health
    should_rate_limit = path.startswith("/api/") and path != "/api/health"

    if should_rate_limit:
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - 60.0

        # Sweep idle IPs periodically (every 1,000 API requests)
        _request_counter += 1
        if _request_counter % 1000 == 0:
            stale_ips = [
                ip for ip, ts in list(_rate_limit_records.items())
                if not ts or ts[-1] <= window_start
            ]
            for ip in stale_ips:
                del _rate_limit_records[ip]

        # Prune old timestamps
        timestamps = [t for t in _rate_limit_records[client_ip] if t > window_start]
        if len(timestamps) >= settings.RATE_LIMIT_PER_MINUTE:
            _rate_limit_records[client_ip] = timestamps
            resp_429 = JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "rate_limit_exceeded",
                    "message": f"Too many requests. Limit is {settings.RATE_LIMIT_PER_MINUTE} requests per minute.",
                },
            )
            origin = request.headers.get("origin")
            if origin:
                resp_429.headers["Access-Control-Allow-Origin"] = origin
                resp_429.headers["Access-Control-Allow-Credentials"] = "true"
                resp_429.headers["Vary"] = "Origin"
            return apply_security_headers(resp_429)

        timestamps.append(now)
        _rate_limit_records[client_ip] = timestamps

    response: Response = await call_next(request)
    return apply_security_headers(response)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Clean validation error response without leaking sensitive payload data."""
    errors = []
    for error in exc.errors():
        field_loc = " -> ".join(str(loc) for loc in error.get("loc", []))
        msg = error.get("msg", "Invalid value")
        errors.append(f"{field_loc}: {msg}")

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "validation_error",
            "message": "Input validation failed: " + "; ".join(errors),
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    error_code = "validation_error" if exc.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY else "http_error"
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": error_code,
            "message": str(exc.detail),
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled server exception processing %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "internal_error",
            "message": "An error occurred while evaluating the submission. Please verify your input and try again.",
        },
    )


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version=settings.ENGINE_VERSION,
        engine="inspectra-rules-v1",
    )


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_submission(payload: AnalyzeRequest):
    """
    Evaluates submitted text, URLs, or app requests.
    Returns explainable verdict, heuristic score, findings, and check statuses.
    Raw submissions are analyzed transiently and never persisted.
    """
    return await process_analysis(payload)


# Mount compiled frontend static assets if built
frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist"))
if os.path.exists(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="static")

