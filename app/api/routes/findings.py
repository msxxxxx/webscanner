from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models import Finding
from app.schemas import FindingRead

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=list[FindingRead])
def list_findings(
    scan_id: int | None = None,
    type: str | None = None,
    severity: str | None = None,
    limit: int = 200,
    db: Session = Depends(get_db),
):
    q = db.query(Finding)
    if scan_id is not None:
        q = q.filter(Finding.scan_id == scan_id)
    if type:
        q = q.filter(Finding.type == type)
    if severity:
        q = q.filter(Finding.severity == severity)
    return q.order_by(Finding.id.desc()).limit(limit).all()