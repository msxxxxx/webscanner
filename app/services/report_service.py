from sqlalchemy.orm import Session

from app.models import DirsearchUrl, Finding, Scan


def build_report_context(db: Session, scan: Scan) -> dict:
    """Возвращает контекст для шаблона report.html."""
    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .order_by(Finding.type, Finding.severity.desc(), Finding.id)
        .all()
    )
    dirsearch_urls = (
        db.query(DirsearchUrl)
        .filter(DirsearchUrl.scan_id == scan.id)
        .all()
    )

    by_type: dict[str, list[Finding]] = {}
    for f in findings:
        by_type.setdefault(f.type, []).append(f)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1

    return {
        "scan": scan,
        "target": scan.target,
        "findings_by_type": by_type,
        "dirsearch_urls": dirsearch_urls,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "total_urls": len(dirsearch_urls),
    }