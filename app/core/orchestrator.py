from datetime import datetime, timezone

from app.core.logging_setup import logger
from app.core.utils import check_hostname
from app.core.tcp import scan_tcp_host
from app.core.ssl import scan_ssl
from app.core.headers import scan_security_headers
from app.core.cert import scan_certificate
from app.core.dirsearch import run_dirsearch
from app.core.nuclei import run_nuclei

ALL_TYPES = ["tcp", "ssl", "headers", "cert", "dirsearch", "nuclei"]


def scan_target(
    host: str,
    scan_types: list[str] | None = None,
    web_ports_filter: list[int] | None = None,
    tcp_ports: list[int] | None = None
) -> dict:
    """Полный скан одного хоста. web_ports_filter — ограничить dirsearch/nuclei."""
    scan_types = scan_types or ALL_TYPES
    need_ports = any(t in scan_types for t in ("ssl", "headers", "cert", "dirsearch", "nuclei"))
    if need_ports and "tcp" not in scan_types:
        scan_types = ["tcp"] + scan_types

    result: dict = {
        "host": host,
        "ip": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "scan_types": scan_types,
        "web_ports_filter": web_ports_filter,
        "tcp": [],
        "web_ports": [],
        "tcp_ports": tcp_ports,
        "ssl": [],
        "headers": [],
        "cert": [],
        "dirsearch": [],
        "nuclei": [],
        "errors": [],
    }

    can_resolve, ip = check_hostname(host)
    result["ip"] = ip
    if not can_resolve:
        result["errors"].append(f"Cannot resolve {host}")
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        return result

    tcp_results, web_ports = scan_tcp_host(host, tcp_ports)
    result["tcp"] = tcp_results
    result["web_ports"] = web_ports

    if not web_ports:
        logger.info("%s: no web ports, skipping web scans", host)
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        return result

    # Фильтр: если пользователь указал порты — только они
    if web_ports_filter:
        filtered = [wp for wp in web_ports if wp["port"] in web_ports_filter]
        if not filtered:
            result["errors"].append(
                f"Requested web ports {web_ports_filter} not among found {[wp['port'] for wp in web_ports]}"
            )
            logger.warning("%s: requested ports %s not found, skipping web scans",
                           host, web_ports_filter)
            result["finished_at"] = datetime.now(timezone.utc).isoformat()
            return result
        web_ports = filtered
        logger.info("%s: filtered to web ports %s", host, web_ports_filter)

    for wp in web_ports:
        port = wp["port"]
        protocol = wp["protocol"]

        if "ssl" in scan_types:
            result["ssl"].extend(scan_ssl(host, port))
        if "headers" in scan_types:
            result["headers"].extend(scan_security_headers(host, port))
        if "cert" in scan_types:
            result["cert"].extend(scan_certificate(host, port))
        if "dirsearch" in scan_types:
            ds = run_dirsearch(host, port, protocol=protocol)
            result["dirsearch"].append(ds)
            if not ds.get("success"):
                result["errors"].append(f"dirsearch {port}: {ds.get('error')}")
        if "nuclei" in scan_types:
            nc = run_nuclei(host, port, protocol=protocol)
            result["nuclei"].append(nc)
            if not nc.get("success"):
                result["errors"].append(f"nuclei {port}: {nc.get('error')}")

    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    return result