from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import Scan, Target
from app.services.target_service import get_or_create_target

VALID_TYPES = {"tcp", "ssl", "headers", "cert", "dirsearch", "nuclei"}


def create_scan(db: Session, host: str, scan_types: list[str]) -> Scan:
    """Создаёт запись Scan (status=pending). Хост резолвится в Target."""
    bad = set(scan_types) - VALID_TYPES
    if bad:
        raise ValueError(f"Unknown scan types: {bad}")
    if not scan_types:
        scan_types = list(VALID_TYPES)

    target = get_or_create_target(db, host)
    scan = Scan(target_id=target.id, status="pending", scan_types=scan_types)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scan(db: Session, scan_id: int) -> Scan | None:
    return db.query(Scan).filter(Scan.id == scan_id).first()


def list_scans_for_target(db: Session, target_id: int, limit: int = 100) -> list[Scan]:
    return (
        db.query(Scan)
        .filter(Scan.target_id == target_id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )


def mark_running(db: Session, scan: Scan) -> None:
    scan.status = "running"
    #scan.started_at = datetime.utcnow()
    scan.started_at = datetime.now(timezone.utc)
    scan.error = None
    db.commit()


def mark_done(db: Session, scan: Scan, raw_result: dict) -> None:
    scan.status = "done"
    scan.finished_at = datetime.now(timezone.utc)
    scan.raw_result = raw_result
    db.commit()


def mark_failed(db: Session, scan: Scan, error: str) -> None:
    scan.status = "failed"
    scan.finished_at = datetime.now(timezone.utc)
    scan.error = error[:2000]
    db.commit()


def list_recent_scans(db: Session, limit: int = 50) -> list[Scan]:
    return (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )


def to_scan_list_item(db: Session, scan: Scan, target_host: str) -> dict:
    from app.models import DirsearchUrl, Finding
    from app.schemas.scan import ScanListItem
    return ScanListItem(
        id=scan.id,
        status=scan.status,
        scan_types=scan.scan_types or [],
        created_at=scan.created_at,
        finished_at=scan.finished_at,
        target_id=scan.target_id,
        target_host=target_host,
        findings_count=db.query(Finding).filter(Finding.scan_id == scan.id).count(),
        urls_count=db.query(DirsearchUrl).filter(DirsearchUrl.scan_id == scan.id).count(),
    )