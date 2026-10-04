"""
ScamShield API.

  POST /api/analyze   multipart form: text (optional), files (0-4: images, PDF, .eml, .txt)
  GET  /api/health

Also serves the front end from ./static so one deployment is enough.
Run locally:  uvicorn server:app --reload --port 8000
"""
import os
import time
from collections import defaultdict, deque
from typing import List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

import app_core
from app_core import UserError

app = FastAPI(title="ScamShield API")

origins = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["*"])

# Simple in-memory per-IP rate limit to protect your API key on a public deployment.
RATE_LIMIT = int(os.environ.get("RATE_LIMIT_PER_HOUR", "40"))
_hits = defaultdict(deque)


def _client_ip(request: Request):
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


def _check_rate(ip):
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > 3600:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many requests. Please try again later.")
    q.append(now)


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "model": app_core.MODEL_NAME,
        "gemini_key": bool(app_core.get_api_key()),
        "safe_browsing_key": bool(os.environ.get("SAFE_BROWSING_API_KEY")),
        "max_files": app_core.MAX_FILES,
        "max_file_bytes": app_core.MAX_FILE_BYTES,
    }


@app.post("/api/analyze")
async def analyze(request: Request, text: Optional[str] = Form(None), files: List[UploadFile] = File(default=[])):
    _check_rate(_client_ip(request))
    if len(files) > app_core.MAX_FILES:
        raise HTTPException(status_code=400, detail=f"Please upload at most {app_core.MAX_FILES} files.")
    payload = []
    for f in files:
        data = await f.read(app_core.MAX_FILE_BYTES + 1)
        if len(data) > app_core.MAX_FILE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"'{f.filename}' is larger than {app_core.MAX_FILE_BYTES // (1024 * 1024)} MB."
            )
        payload.append((f.filename, f.content_type, data))
    try:
        # analyze() is blocking (network + LLM), so run it off the event loop
        from starlette.concurrency import run_in_threadpool
        return await run_in_threadpool(app_core.analyze, text or "", payload)
    except UserError as e:
        return JSONResponse(status_code=e.status, content={"detail": str(e)})
    except Exception:
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"detail": "Something went wrong while analysing. Please try again."})


STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.isdir(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
