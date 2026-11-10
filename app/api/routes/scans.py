from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models import DirsearchUrl, Finding, Scan, Target
from app.schemas import ScanCreate, ScanListItem, ScanRead, ScanStatus
from app.services import scan_service
from app.workers.scan_worker import run_scan_job

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanRead, status_code=201)
def create_scan(
    payload: ScanCreate,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
):
    try:
        scan = scan_service.create_scan(db, payload.host, payload.scan_types, payload.web_ports, payload.tcp_ports)
    except ValueError as e:
        raise HTTPException(400, str(e))

    background.add_task(run_scan_job, scan.id)
    return scan


@router.get("", response_model=list[ScanListItem])
def list_scans(limit: int = 50, db: Session = Depends(get_db)):
    rows = (
        db.query(Scan, Target)
        .join(Target, Scan.target_id == Target.id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )
    return [scan_service.to_scan_list_item(db, s, t.host) for s, t in rows]


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = scan_service.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.get("/{scan_id}/status", response_model=ScanStatus)
def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = scan_service.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return ScanStatus(
        id=scan.id,
        status=scan.status,
        error=scan.error,
        findings_count=db.query(Finding).filter(Finding.scan_id == scan.id).count(),
        urls_count=db.query(DirsearchUrl).filter(DirsearchUrl.scan_id == scan.id).count(),
    )


@router.get("/{scan_id}/raw")
def get_scan_raw(scan_id: int, db: Session = Depends(get_db)):
    scan = scan_service.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan.raw_result or {}
