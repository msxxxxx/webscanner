from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.routes import findings, reports, scans, targets
from app.config import settings  # noqa: F401 — загружает .env

from app.database import SessionLocal
from app.models import Scan

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import time
STATIC_VERSION = int(time.time())


@asynccontextmanager
async def lifespan(app: FastAPI):
    # при старте: всё, что осталось в running/pending — сироты от прошлого процесса
    db = SessionLocal()
    try:
        stuck = db.query(Scan).filter(Scan.status.in_(["running", "pending"])).all()
        if stuck:
            for s in stuck:
                s.status = "failed"
                s.error = (s.error or "") + " | Interrupted: server restarted"
                s.finished_at = datetime.now(timezone.utc)
            db.commit()
            print(f"⚠ Marked {len(stuck)} stale scans as failed")
    finally:
        db.close()
    yield

    
app = FastAPI(title="myscanner", version="0.1.0", lifespan=lifespan)

# Jinja2 + статика
templates = Jinja2Templates(directory="app/templates")
app.state.templates = templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# API
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(reports.router)


@app.get("/")
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"static_version": STATIC_VERSION})


@app.get("/scans/{scan_id}")
def scan_page(scan_id: int, request: Request):
    return templates.TemplateResponse(request, "scan_detail.html", {"scan_id": scan_id})


@app.get("/health")
def health():
    return {"status": "ok"}