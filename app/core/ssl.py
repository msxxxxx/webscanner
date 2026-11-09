import nmap
from app.core.logging_setup import logger


def scan_ssl(target: str, port: int) -> list[str]:
    try:
        logger.info("SSL scan %s:%s", target, port)
        scanner = nmap.PortScanner()
        scanner.scan(target, arguments=f"-p {port} --script ssl-enum-ciphers,ssl-cert,ssl-date")

        results: list[str] = []
        for host in scanner.all_hosts():
            if "tcp" not in scanner[host] or port not in scanner[host]["tcp"]:
                continue
            info = scanner[host]["tcp"][port]
            results.append(f"\n------ SSL Ciphers Scan ------")
            results.append(f"Host: {host} | Port: {port}")
            results.append(f"Service: {info.get('name', 'unknown')}")
            results.append(f"State: {info.get('state', 'unknown')}")

            script = info.get("script", {})
            cipher_info = script.get("ssl-enum-ciphers")
            if isinstance(cipher_info, dict):
                results.append("\nSSL Ciphers Information:")
                for proto, data in cipher_info.items():
                    if isinstance(data, dict):
                        results.append(f"\n{proto}:")
                        for c in data.get("ciphers", []):
                            results.append(f"  - {c}")
            elif cipher_info:
                results.append(f"\nSSL Ciphers Information:\n{cipher_info}")
            else:
                results.append("\nNo SSL cipher information available")

        return results or ["No SSL information available"]
    except Exception as e:
        logger.exception("SSL scan failed %s:%s", target, port)
        return [f"Error during SSL scan on {target}:{port}: {e}"]