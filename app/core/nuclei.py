import os
import subprocess
import tempfile

from app.config import settings
from app.core.logging_setup import logger
from app.core.utils import guess_protocol


def _get_nuclei_bin() -> str | None:
    if os.path.exists(settings.NUCLEI_BIN):
        return settings.NUCLEI_BIN
    # fallback: в PATH
    from shutil import which
    return which("nuclei")


def run_nuclei(target: str, port: int | None = None, protocol: str | None = None) -> dict:
    nuclei_bin = _get_nuclei_bin()
    if not nuclei_bin:
        return {"success": False, "error": "nuclei not installed"}

    if port:
        proto = protocol or guess_protocol(port)
        url = f"{proto}://{target}:{port}"
    else:
        url = f"https://{target}"

    with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False) as tmp:
        output_file = tmp.name

    try:
        cmd = [
            nuclei_bin, "-u", url, "-o", output_file,
            "-silent", "-stats",
            "-severity", "low,medium,high,critical",
        ]
        logger.info("nuclei: %s", " ".join(cmd))
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=settings.NUCLEI_TIMEOUT,
        )

        findings: list[str] = []
        if os.path.exists(output_file):
            with open(output_file, encoding="utf-8", errors="ignore") as f:
                findings = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

        logger.info("nuclei %s: %d findings", url, len(findings))
        return {
            "success": True,
            "url": url,
            "port": port,
            "protocol": protocol or (guess_protocol(port) if port else "https"),
            "findings": findings,
            "total_findings": len(findings),
            "stderr": proc.stderr[-2000:] if proc.stderr else "",
        }
    except subprocess.TimeoutExpired:
        logger.error("nuclei timeout for %s", url)
        return {"success": False, "url": url, "port": port, "error": "Timeout"}
    except Exception as e:
        logger.exception("nuclei failed for %s", url)
        return {"success": False, "url": url, "port": port, "error": str(e)}
    finally:
        if os.path.exists(output_file):
            try:
                os.remove(output_file)
            except OSError:
                pass