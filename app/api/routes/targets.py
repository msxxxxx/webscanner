from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models import DirsearchUrl, Finding, Scan
from app.schemas import ScanListItem, TargetCreate, TargetRead
from app.services import target_service, scan_service

router = APIRouter(prefix="/api/targets", tags=["targets"])


@router.get("", response_model=list[TargetRead])
def list_targets(db: Session = Depends(get_db)):
    return target_service.list_targets(db)


@router.post("", response_model=TargetRead, status_code=201)
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    return target_service.get_or_create_target(db, payload.host)


@router.get("/{target_id}", response_model=TargetRead)
def get_target(target_id: int, db: Session = Depends(get_db)):
    t = target_service.get_target(db, target_id)
    if not t:
        raise HTTPException(404, "Target not found")
    return t


@router.get("/{target_id}/scans", response_model=list[ScanListItem])
def list_target_scans(target_id: int, limit: int = 50, db: Session = Depends(get_db)):
    target = target_service.get_target(db, target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    scans = scan_service.list_scans_for_target(db, target_id, limit)
    return [scan_service.to_scan_list_item(db, s, target.host) for s in scans]