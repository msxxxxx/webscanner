import nmap
from app.core.logging_setup import logger


def scan_certificate(target: str, port: int) -> list[str]:
    try:
        logger.info("Cert scan %s:%s", target, port)
        scanner = nmap.PortScanner()
        scanner.scan(target, arguments=f"-p {port} --script ssl-cert")

        results: list[str] = []
        for host in scanner.all_hosts():
            if "tcp" not in scanner[host] or port not in scanner[host]["tcp"]:
                continue
            info = scanner[host]["tcp"][port]
            results.append(f"\n------ Certificate Scan ------")
            results.append(f"Host: {host} | Port: {port}")

            cert = info.get("script", {}).get("ssl-cert")
            if isinstance(cert, str):
                results.append("Certificate Information:")
                results.append(cert)
            elif isinstance(cert, dict):
                results.append("Structured Certificate Information:")
                for key in ("Subject", "Issuer", "Not valid before", "Not valid after"):
                    if key in cert:
                        results.append(f"{key}: {cert[key]}")
            else:
                results.append("No certificate information available")

        return results or ["No certificate information available"]
    except Exception as e:
        logger.exception("Cert scan failed %s:%s", target, port)
        return [f"Error during certificate scan on {target}:{port}: {e}"]