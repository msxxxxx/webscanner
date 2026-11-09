from datetime import datetime
from sqlalchemy import String, DateTime, ForeignKey, func, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

# JSONB на постгресе, JSON на sqlite (для тестов)
JSONType = JSONB().with_variant(JSON, "sqlite")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)

    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending/running/done/failed
    scan_types: Mapped[list] = mapped_column(JSONType, default=list)                # ["tcp","ssl","dirsearch","nuclei"]

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(String(2000), nullable=True)

    raw_result: Mapped[dict] = mapped_column(JSONType, default=dict)                # полный снапшот результатов
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    target: Mapped["Target"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    dirsearch_urls: Mapped[list["DirsearchUrl"]] = relationship(back_populates="scan", cascade="all, delete-orphan")