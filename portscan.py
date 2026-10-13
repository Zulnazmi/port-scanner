#!/usr/bin/env python3
"""portscan - a small multithreaded TCP port scanner with banner grabbing.

For educational use and authorized testing only. Only scan systems you own
or have explicit written permission to test.
"""
import argparse
import csv
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb",
}

# Protocols that wait for the client to speak first need a probe to elicit a banner.
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
HTTP_PORTS = {80, 8080, 8000, 8008, 8888}


def parse_ports(spec):
    """Parse '22,80,1000-1010' into a sorted list of unique ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                raise ValueError(f"invalid range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"ports out of range (1-65535): {sorted(bad)[:5]}")
    return sorted(ports)


def grab_banner(sock, host, port):
    """Try to read a service banner; send an HTTP probe on web ports."""
    try:
        if port in HTTP_PORTS:
            sock.sendall(HTTP_PROBE.replace(b"{host}", host.encode()))
        data = sock.recv(256)
        text = data.decode("utf-8", errors="replace").strip()
        return text.splitlines()[0][:120] if text else ""
    except (socket.timeout, OSError):
        return ""


def scan_port(host, port, timeout, grab):
    """Return a result dict if the port is open, else None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = grab_banner(sock, host, port) if grab else ""
            return {
                "port": port,
                "state": "open",
                "service": COMMON_SERVICES.get(port, "unknown"),
                "banner": banner,
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan(host, ports, timeout=1.0, threads=100, grab=True):
    results = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(scan_port, host, p, timeout, grab) for p in ports]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)
    return sorted(results, key=lambda r: r["port"])


def write_output(path, host, ip, results):
    if path.endswith(".csv"):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["port", "state", "service", "banner"])
            w.writeheader()
            w.writerows(results)
    else:
        payload = {
            "target": host,
            "ip": ip,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "open_ports": results,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Multithreaded TCP port scanner with banner grabbing. "
                    "Authorized use only.")
    ap.add_argument("target", help="hostname or IP address to scan")
    ap.add_argument("-p", "--ports", default="1-1024",
                    help="ports, e.g. 22,80,443 or 1-1024 (default: 1-1024)")
    ap.add_argument("-t", "--timeout", type=float, default=1.0,
                    help="per-port timeout in seconds (default: 1.0)")
    ap.add_argument("-T", "--threads", type=int, default=100,
                    help="number of worker threads (default: 100)")
    ap.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    ap.add_argument("-o", "--output", help="save results to .json or .csv file")
    args = ap.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
        ip = socket.gethostbyname(args.target)
    except ValueError as e:
        ap.error(str(e))
    except socket.gaierror:
        print(f"error: cannot resolve host '{args.target}'", file=sys.stderr)
        return 2

    print(f"Scanning {args.target} ({ip}) - {len(ports)} ports, {args.threads} threads")
    start = datetime.now()
    results = scan(args.target, ports, args.timeout, args.threads, not args.no_banner)
    elapsed = (datetime.now() - start).total_seconds()

    if results:
        print(f"\n{'PORT':<8}{'STATE':<8}{'SERVICE':<14}BANNER")
        for r in results:
            print(f"{r['port']:<8}{r['state']:<8}{r['service']:<14}{r['banner']}")
    else:
        print("\nNo open ports found.")
    print(f"\nDone: {len(results)} open port(s) in {elapsed:.2f}s")

    if args.output:
        write_output(args.output, args.target, ip, results)
        print(f"Results saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
