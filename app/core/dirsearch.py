import os
import subprocess
import tempfile

from app.config import settings
from app.core.logging_setup import logger
from app.core.utils import guess_protocol


def _get_dirsearch_python() -> str | None:
    """В Docker всегда системный python3 — venv не нужен."""
    if not os.path.exists(settings.DIRSEARCH_PATH):
        logger.error("dirsearch not found at %s", settings.DIRSEARCH_PATH)
        return None
    return "python3"


def run_dirsearch(target: str, port: int | None = None, protocol: str | None = None) -> dict:
    """Запуск dirsearch. Возвращает {success, url, port, urls, total_urls, ...}."""
    ds_python = _get_dirsearch_python()
    if ds_python is None:
        return {"success": False, "error": "dirsearch not installed"}

    if port:
        proto = protocol or guess_protocol(port)
        url = f"{proto}://{target}:{port}"
    else:
        url = f"https://{target}"

    with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False) as tmp:
        output_file = tmp.name

    try:
        cmd = [
            ds_python, settings.DIRSEARCH_PATH,
            "-u", url,
            "-o", output_file,
            "--random-agent",
            "-t", "20",                 # потоков больше — быстрее
            "--timeout", "5",           # таймаут одного HTTP-запроса
            "--retries", "1",           # меньше ретраев — быстрее
            "--exclude-status", "404,400",
            "--full-url",
            "--no-color",
            #"-q",
        ]
        logger.info("dirsearch: %s", " ".join(cmd))
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE,
            #stderr=subprocess.PIPE,
            text=True,
            timeout=settings.DIRSEARCH_TIMEOUT,
            cwd=settings.DIRSEARCH_DIR,
        )

        urls: list[str] = []
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") \
                            and not line.startswith("[") \
                            and not line.startswith("Time"):
                        urls.append(line)

        logger.info("dirsearch %s: %d URLs", url, len(urls))
        return {
            "success": True,
            "url": url,
            "port": port,
            "protocol": protocol or (guess_protocol(port) if port else "https"),
            "urls": urls,
            "total_urls": len(urls),
            "raw_output": proc.stdout[-5000:],  # хвост для диагностики
            "stderr": proc.stderr[-2000:] if proc.stderr else "",
        }
    except subprocess.TimeoutExpired:
        logger.error("dirsearch timeout for %s", url)
        return {"success": False, "url": url, "port": port, "error": "Timeout"}
    except Exception as e:
        logger.exception("dirsearch failed for %s", url)
        return {"success": False, "url": url, "port": port, "error": str(e)}
    finally:
        if os.path.exists(output_file):
            try:
                os.remove(output_file)
            except OSError:
                pass