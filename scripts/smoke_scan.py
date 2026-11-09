"""Ручной смоук-тест: создать скан и прогнать его синхронно.
Запуск: .venv/bin/python -m scripts.smoke_scan 172.27.167.51 tcp
"""
import sys

from app.database import SessionLocal
from app.models import Finding, DirsearchUrl
from app.services import scan_service
from app.workers.scan_worker import run_scan_job


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "172.27.167.51"
    types = sys.argv[2].split(",") if len(sys.argv) > 2 else ["tcp"]

    db = SessionLocal()
    try:
        scan = scan_service.create_scan(db, host, types)
        scan_id = scan.id
        print(f"Created scan id={scan_id} host={host} types={types}")
    finally:
        db.close()

    # запускаем синхронно (в реальном приложении — BackgroundTasks)
    run_scan_job(scan_id)

    db = SessionLocal()
    try:
        scan = scan_service.get_scan(db, scan_id)
        print(f"\n=== Scan {scan_id} status: {scan.status} ===")
        if scan.error:
            print(f"ERROR: {scan.error}")

        print(f"Findings: {db.query(Finding).filter_by(scan_id=scan_id).count()}")
        for f in db.query(Finding).filter_by(scan_id=scan_id).limit(10):
            print(f"  [{f.type}/{f.severity}] {f.title[:100]}")
        print(f"Dirsearch URLs: {db.query(DirsearchUrl).filter_by(scan_id=scan_id).count()}")
    finally:
        db.close()


if __name__ == "__main__":
    main()