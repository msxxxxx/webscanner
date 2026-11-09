import socket
from app.core.logging_setup import logger


def check_hostname(hostname: str) -> tuple[bool, str | None]:
    """Резолвит хост в IP. Возвращает (ok, ip)."""
    try:
        ip = socket.gethostbyname(hostname)
        logger.info("%s resolved to %s", hostname, ip)
        return True, ip
    except socket.gaierror as e:
        logger.warning("Cannot resolve %s: %s", hostname, e)
        return False, None


def guess_protocol(port: int) -> str:
    """Грубая эвристика: 443/8443/9443 → https, иначе http."""
    if "443" in str(port):
        return "https"
    return "http"


def to_lines(items) -> list[str]:
    """Безопасно превращает список любых элементов в список строк (для HTML/JSON)."""
    if not items:
        return ["No data"]
    result = []
    for item in items:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            if item.get("success") is False:
                result.append(f"[FAIL] {item.get('error', 'unknown error')}")
            elif "urls" in item:
                result.append(
                    f"URL: {item.get('url', '?')} | URLs: {item.get('total_urls', 0)}"
                )
                result.extend(f"   • {u}" for u in item.get("urls", [])[:50])
            elif "findings" in item:
                result.append(
                    f"URL: {item.get('url', '?')} | Findings: {item.get('total_findings', 0)}"
                )
                result.extend(f"   • {f}" for f in item.get("findings", [])[:50])
            else:
                result.append(str(item))
        else:
            result.append(str(item))
    return result