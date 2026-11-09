import nmap
from app.core.logging_setup import logger

COMMON_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cache-Control",
]


def scan_security_headers(target: str, port: int) -> list[str]:
    try:
        logger.info("Headers scan %s:%s", target, port)
        scanner = nmap.PortScanner()
        scanner.scan(target,
                     arguments=f"-p {port} --script http-security-headers,http-headers")

        results: list[str] = []
        for host in scanner.all_hosts():
            if "tcp" not in scanner[host] or port not in scanner[host]["tcp"]:
                continue
            info = scanner[host]["tcp"][port]
            results.append(f"\n------ Security Headers Scan ------")
            results.append(f"Host: {host} | Port: {port}")
            results.append(f"Service: {info.get('name', 'unknown')}")

            headers_text = ""
            for sn in ("http-security-headers", "http-headers"):
                out = info.get("script", {}).get(sn)
                if isinstance(out, str):
                    headers_text += out + "\n"
                elif isinstance(out, dict):
                    for k, v in out.items():
                        headers_text += f"{k}: {v}\n"

            if headers_text:
                results.append(f"\nRaw Headers:\n{headers_text}")

            found = [h for h in COMMON_HEADERS if h.lower() in headers_text.lower()]
            missing = [h for h in COMMON_HEADERS if h.lower() not in headers_text.lower()]
            if found:
                results.append(f"\n✓ Found: {', '.join(found)}")
            if missing:
                results.append(f"\n✗ Missing: {', '.join(missing)}")

        return results or ["No security headers information available"]
    except Exception as e:
        logger.exception("Headers scan failed %s:%s", target, port)
        return [f"Error during security headers scan on {target}:{port}: {e}"]