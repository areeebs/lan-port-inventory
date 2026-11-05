from __future__ import annotations
import argparse, ipaddress, json, socket, sys
from concurrent.futures import ThreadPoolExecutor

DEFAULT_PORTS = [22, 53, 80, 135, 139, 443, 445, 3389]
MAX_PORTS = 32

def validate_target(value):
    try: ip = ipaddress.ip_address(value)
    except ValueError as e: raise ValueError("Use a single IPv4 address; hostnames and CIDRs are rejected.") from e
    rfc1918 = ip.version == 4 and any(ip in ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if not rfc1918:
        raise ValueError("Target must be an RFC1918 private IPv4 address.")
    return str(ip)

def validate_ports(ports):
    unique = sorted(set(ports))
    if not unique or len(unique) > MAX_PORTS or any(not isinstance(p, int) or p < 1 or p > 65535 for p in unique):
        raise ValueError("Provide 1–32 distinct TCP ports in the range 1–65535.")
    return unique

def probe(target, port, timeout=0.4, connector=socket.create_connection):
    try:
        with connector((target, port), timeout=timeout): return {"port": port, "state": "open"}
    except (ConnectionRefusedError,): return {"port": port, "state": "closed"}
    except (TimeoutError, OSError): return {"port": port, "state": "filtered_or_unreachable"}

def scan(target, ports, timeout=0.4):
    target = validate_target(target); ports = validate_ports(ports)
    with ThreadPoolExecutor(max_workers=min(8, len(ports))) as pool:
        results = list(pool.map(lambda p: probe(target, p, timeout), ports))
    return {"target": target, "protocol": "TCP", "ports_checked": len(ports), "results": results,
            "payloads_sent": False}

def main():
    p = argparse.ArgumentParser(description="Bounded TCP inventory for one authorized RFC1918 host.")
    p.add_argument("target"); p.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)))
    p.add_argument("--timeout", type=float, default=0.4); a = p.parse_args()
    try:
        if not 0.1 <= a.timeout <= 2: raise ValueError("Timeout must be between 0.1 and 2 seconds.")
        ports = [int(x) for x in a.ports.split(",")]
        print(json.dumps(scan(a.target, ports, a.timeout), indent=2))
    except ValueError as e: print(json.dumps({"error": str(e)}), file=sys.stderr); return 2
    return 0

if __name__ == "__main__": raise SystemExit(main())
