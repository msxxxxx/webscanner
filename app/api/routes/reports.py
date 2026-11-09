from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.services import report_service, scan_service

router = APIRouter(prefix="/reports", tags=["reports"])


def _templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates


@router.get("/{scan_id}.html")
def report_html(scan_id: int, request: Request, db: Session = Depends(get_db)):
    scan = scan_service.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    ctx = report_service.build_report_context(db, scan)
    return _templates(request).TemplateResponse(request, "report.html", ctx)


@router.get("/{scan_id}.json")
def report_json(scan_id: int, db: Session = Depends(get_db)):
    scan = scan_service.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return report_service.build_report_context(db, scan)