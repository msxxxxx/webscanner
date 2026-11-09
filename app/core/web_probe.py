import re
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from app.core.logging_setup import logger

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Порты, которые почти никогда не web — не тратим на них HTTP-пробы
NON_WEB_PORTS = {
    21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 161, 389,
    445, 465, 587, 636, 993, 995, 1433, 1521, 3306, 3389,
    5432, 5900, 6379, 11211, 27017,
}

NON_WEB_SERVICES = {
    "ssh", "ftp", "smtp", "imap", "pop3", "mysql",
    "postgresql", "redis", "mssql", "mongodb", "telnet",
}


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:100] if m else ""


def is_web_port(port: int, host: str, timeout: int = 3) -> tuple[bool, str | None, dict]:
    """
    Проверяет порт HTTP-запросом.
    Возвращает (is_web, protocol, details). True — только если реально пришёл HTTP-ответ.
    """
    protocols = ["https", "http"] if port in (443, 8443, 9443, 4443) else ["http", "https"]

    for proto in protocols:
        url = f"{proto}://{host}:{port}"
        try:
            r = requests.get(
                url, timeout=timeout, verify=False, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; PortScanner/1.0)"},
            )
            # любой HTTP-ответ — это web
            return True, proto, {
                "status_code": r.status_code,
                "server": r.headers.get("Server", "unknown"),
                "content_type": r.headers.get("Content-Type", "unknown"),
                "title": _extract_title(r.text),
                "url": url,
            }
        except requests.exceptions.SSLError:
            # TLS-хендшейк не удался — это НЕ признак web (SSH, SMTP и т.п.)
            logger.debug("%s: SSLError, not web", url)
            continue
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.RequestException) as e:
            logger.debug("%s: %s, not web", url, type(e).__name__)
            continue

    return False, None, {}


def get_web_ports(scanner, host: str) -> list[dict]:
    """Возвращает веб-порты для хоста: [{port, protocol, details, service_name}]."""
    web_ports: list[dict] = []
    if "tcp" not in scanner[host]:
        return web_ports

    for port, info in scanner[host]["tcp"].items():
        if info.get("state") != "open":
            continue

        # быстрый фильтр по порту
        if port in NON_WEB_PORTS:
            logger.info("Port %s in NON_WEB_PORTS, skip", port)
            continue

        # быстрый фильтр по имени сервиса
        service = (info.get("name") or "").lower()
        if service in NON_WEB_SERVICES:
            logger.info("Port %s service=%s non-web, skip", port, service)
            continue

        is_web, proto, details = is_web_port(port, host)
        if is_web:
            logger.info("WEB port %s://%s:%s [%s]",
                        proto, host, port, details.get("status_code", "?"))
            web_ports.append({
                "port": port,
                "protocol": proto,
                "details": details,
                "service_name": info.get("name", ""),
                "service_version": info.get("version", ""),
            })
        else:
            logger.info("Port %s not web", port)
    return web_ports