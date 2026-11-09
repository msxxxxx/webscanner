from sqlalchemy.orm import Session

from app.core.utils import check_hostname
from app.models import Target


def get_or_create_target(db: Session, host: str) -> Target:
    """Возвращает существующий Target или создаёт новый (с резолвом IP)."""
    target = db.query(Target).filter(Target.host == host).first()
    if target:
        return target

    _, ip = check_hostname(host)
    target = Target(host=host, ip=ip)
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


def list_targets(db: Session) -> list[Target]:
    return db.query(Target).order_by(Target.created_at.desc()).all()


def get_target(db: Session, target_id: int) -> Target | None:
    return db.query(Target).filter(Target.id == target_id).first()