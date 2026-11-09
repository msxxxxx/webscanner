from sqlalchemy import String, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class DirsearchUrl(Base):
    __tablename__ = "dirsearch_urls"
    __table_args__ = (UniqueConstraint("scan_id", "url", name="uq_scan_url"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2000))
    status_code: Mapped[int | None] = mapped_column(nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="dirsearch_urls")