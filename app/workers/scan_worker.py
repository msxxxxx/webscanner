from app.core.logging_setup import logger
from app.core.orchestrator import scan_target
from app.database import SessionLocal
from app.models import DirsearchUrl, Finding, Scan
from app.services import scan_service


def run_scan_job(scan_id: int) -> None:
    """Фоновая задача: выполнить скан и записать результаты в БД."""
    db = SessionLocal()
    try:
        scan = scan_service.get_scan(db, scan_id)
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return

        host = scan.target.host
        logger.info("Starting scan %s for %s (%s)", scan_id, host, scan.scan_types)
        scan_service.mark_running(db, scan)

        try:
            raw = scan_target(host, scan.scan_types, scan.web_ports, scan.tcp_ports)
        except Exception as e:
            logger.exception("scan_target crashed for %s", host)
            scan_service.mark_failed(db, scan, f"scan_target crashed: {e}")
            return

        _persist_results(db, scan, raw)
        scan_service.mark_done(db, scan, raw)
        logger.info("Scan %s done: %d dirsearch, %d nuclei",
                    scan_id, len(raw.get("dirsearch", [])), len(raw.get("nuclei", [])))

    except Exception as e:
        logger.exception("run_scan_job failed for scan %s", scan_id)
        try:
            scan = scan_service.get_scan(db, scan_id)
            if scan:
                scan_service.mark_failed(db, scan, str(e))
        except Exception:
            logger.exception("Failed to mark scan %s as failed", scan_id)
    finally:
        db.close()


def _persist_results(db, scan: Scan, raw: dict) -> None:
    """Раскладывает raw-результат по таблицам findings и dirsearch_urls."""

    # --- TCP порты как findings типа tcp ---
    for line in raw.get("tcp", []):
        if isinstance(line, str) and line.strip().startswith("Port:"):
            db.add(Finding(
                scan_id=scan.id,
                type="tcp",
                severity="info",
                title=line.strip()[:500],
                evidence={"raw": line.strip()},
            ))

    # --- web_ports ---
    for wp in raw.get("web_ports", []):
        db.add(Finding(
            scan_id=scan.id,
            type="web_port",
            severity="info",
            title=f"{wp['protocol']}://{scan.target.host}:{wp['port']}",
            url=wp["details"].get("url"),
            evidence=wp,
        ))

    # --- SSL / headers / cert — каждая строка как finding ---
    for category in ("ssl", "headers", "cert"):
        for line in raw.get(category, []):
            if isinstance(line, str) and line.strip():
                db.add(Finding(
                    scan_id=scan.id,
                    type=category,
                    severity="info",
                    title=line.strip()[:500],
                    evidence={"raw": line.strip()},
                ))

    # --- dirsearch: URL'ы в отдельную таблицу + сводка в findings ---
    for ds in raw.get("dirsearch", []):
        if ds.get("success"):
            for url in ds.get("urls", []):
                db.add(DirsearchUrl(scan_id=scan.id, url=url[:2000]))
            db.add(Finding(
                scan_id=scan.id,
                type="dirsearch",
                severity="info",
                title=f"dirsearch {ds.get('url')}: {ds.get('total_urls', 0)} URLs",
                url=ds.get("url"),
                evidence={
                    "port": ds.get("port"),
                    "protocol": ds.get("protocol"),
                    "total_urls": ds.get("total_urls", 0),
                },
            ))
        else:
            db.add(Finding(
                scan_id=scan.id,
                type="dirsearch_error",
                severity="low",
                title=f"dirsearch failed on {ds.get('url', '?')}",
                evidence={"error": ds.get("error")},
            ))

    # --- nuclei: находки как отдельные findings ---
    for nc in raw.get("nuclei", []):
        if nc.get("success"):
            for fnd in nc.get("findings", []):
                # nuclei -silent выводит строки вида "[cve-2024-xxx] [http] [high] http://..."
                severity = _extract_severity(fnd)
                db.add(Finding(
                    scan_id=scan.id,
                    type="nuclei",
                    severity=severity,
                    title=fnd.strip()[:500],
                    url=nc.get("url"),
                    evidence={"port": nc.get("port"), "raw": fnd.strip()},
                ))
        else:
            db.add(Finding(
                scan_id=scan.id,
                type="nuclei_error",
                severity="low",
                title=f"nuclei failed on {nc.get('url', '?')}",
                evidence={"error": nc.get("error")},
            ))

    # --- ошибки оркестратора ---
    for err in raw.get("errors", []):
        db.add(Finding(
            scan_id=scan.id,
            type="scan_error",
            severity="low",
            title=str(err)[:500],
            evidence={},
        ))

    db.commit()


def _extract_severity(nuclei_line: str) -> str:
    """Пытается вытащить severity из строки nuclei. По умолчанию — info."""
    for sev in ("critical", "high", "medium", "low", "info"):
        if f"[{sev}]" in nuclei_line.lower():
            return sev
    return "info"