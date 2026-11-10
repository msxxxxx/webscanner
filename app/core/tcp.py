import nmap

from app.core.logging_setup import logger
from app.core.web_probe import get_web_ports


def scan_tcp_host(target: str, ports: list[int] | None = None) -> tuple[list[str], list[dict]]:
    """Сканирует TCP-порты и возвращает (tcp_results, web_ports)."""
    try:
        if ports is None:
            port_arg = "--top-ports 1000"
        elif len(ports) == 0:
            port_arg = "-p-"
        else:
            port_arg = f"-p {','.join(map(str, ports))}"
        
        logger.info("Starting TCP scan for %s (ports=%s)", target, port_arg)
        scanner = nmap.PortScanner()
        scanner.scan(
            target,
            arguments=f"-sV -Pn {port_arg} --open --host-timeout 5m --min-rate 500",
        )

        results: list[str] = []
        all_web_ports: list[dict] = []

        hosts = scanner.all_hosts()
        if not hosts:
            logger.warning("nmap returned no hosts for %s", target)
            return [f"No response from {target}"], []

        for host in hosts:
            results.append("\n------ TCP Port Scan Results ------")
            results.append(f"Host: {target} ({scanner[host].hostname()})")
            results.append(f"IP Address: {scanner[host]['addresses'].get('ipv4', 'N/A')}")
            results.append(f"Status: {scanner[host].state()}")

            if not scanner[host].all_protocols():
                results.append("No open ports found")
                continue  # ← не return, а continue — идём к следующему host

            for proto in scanner[host].all_protocols():
                open_count = 0
                for port, info in scanner[host][proto].items():
                    if info["state"] == "open":
                        open_count += 1
                        results.append(
                            f"Port: {port:5} | Protocol: {proto:4} | "
                            f"Service: {info.get('name', 'unknown'):15} | "
                            f"Version: {info.get('product', 'unknown')} "
                            f"{info.get('version', '')}"
                        )
                results.append(f"Total open {proto} ports: {open_count}")

            # ← get_web_ports для КАЖДОГО host, внутри цикла
            host_web_ports = get_web_ports(scanner, host)
            all_web_ports.extend(host_web_ports)

        if all_web_ports:
            ports_str = ", ".join(
                f"{wp['protocol']}://{wp['port']}" for wp in all_web_ports
            )
            results.append(f"\nFound web ports: {ports_str}")
        else:
            results.append("\nNo web ports found")

        return results, all_web_ports

    except Exception as e:
        logger.exception("TCP scan failed for %s", target)
        return [f"Error scanning {target}: {e}"], []