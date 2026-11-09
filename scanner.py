#!/usr/bin/env python3
"""TCP connect port scanner with service/version detection (v2).

Only scan hosts you own or have explicit permission to test
(localhost, your own VMs, scanme.nmap.org, TryHackMe/lab machines).

Usage:
    python3 scanner.py 127.0.0.1
    python3 scanner.py scanme.nmap.org -p 1-1024 -t 0.5 -w 200
    python3 scanner.py 10.10.10.10 -p 22,80,443 --json scan.json
    python3 cve_lookup.py --scan scan.json
"""
import argparse
import json
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888}
TLS_PORTS = {443, 8443}

# (regex, service, product). Group 1, if present, is the version.
SIGNATURES = [
    (r"SSH-\d\.\d+-OpenSSH_(\S+)", "ssh", "OpenSSH"),
    (r"SSH-\d\.\d+-dropbear_(\S+)", "ssh", "Dropbear"),
    (r"\(vsFTPd ([\d.]+)\)", "ftp", "vsFTPd"),
    (r"ProFTPD ([\d.]+\w*)", "ftp", "ProFTPD"),
    (r"Pure-FTPd", "ftp", "Pure-FTPd"),
    (r"Server:\s*Apache/([\d.]+)", "http", "Apache httpd"),
    (r"Server:\s*nginx/([\d.]+)", "http", "nginx"),
    (r"Server:\s*Microsoft-IIS/([\d.]+)", "http", "Microsoft IIS"),
    (r"Server:\s*lighttpd/([\d.]+)", "http", "lighttpd"),
    (r"Exim ([\d.]+)", "smtp", "Exim"),
    (r"ESMTP Postfix", "smtp", "Postfix"),
    (r"Dovecot", "imap/pop3", "Dovecot"),
]
MYSQL_RE = re.compile(r"^.{4}\x0a(\d+\.\d+\.\d+[\w.\-+]*)\x00", re.S)
SERVER_HDR_RE = re.compile(r"Server:\s*([^\s/\r\n]+)/?([\w.\-]*)", re.I)


def parse_ports(spec: str) -> list[int]:
    """Turn '22,80,100-200' into a sorted list of unique ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"ports out of range 1-65535: {bad[:5]}")
    return sorted(ports)


def scan_port(host: str, port: int, timeout: float) -> bool:
    """Return True if a full TCP connection to host:port succeeds."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except OSError:
        return False


def _recv(sock) -> bytes:
    try:
        return sock.recv(2048)
    except OSError:  # includes timeouts
        return b""


def grab_banner(host: str, port: int, timeout: float) -> str:
    """Connect and read whatever the service says, probing HTTP if it stays quiet."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return ""
    try:
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock)
        sock.settimeout(timeout)
        data = b""
        if port not in HTTP_PORTS and port not in TLS_PORTS:
            data = _recv(sock)  # SSH, FTP, SMTP, MySQL... speak first
        if not data:
            probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: port-scanner/2.0\r\n\r\n"
            sock.sendall(probe.encode())
            data = _recv(sock)
        return data.decode("latin-1")
    except OSError:
        return ""
    finally:
        sock.close()


def identify(port: int, banner: str) -> dict:
    """Map a raw banner to service / product / version."""
    info = {"service": "", "product": "", "version": ""}

    m = MYSQL_RE.match(banner)
    if m:
        info.update(service="mysql", version=m.group(1),
                    product="MariaDB" if "MariaDB" in m.group(1) else "MySQL")
    else:
        for pattern, service, product in SIGNATURES:
            m = re.search(pattern, banner, re.I)
            if m:
                info.update(service=service, product=product,
                            version=m.group(1) if m.lastindex else "")
                break
        else:
            m = SERVER_HDR_RE.search(banner)
            if m:
                info.update(service="http", product=m.group(1), version=m.group(2))
            elif banner.startswith("HTTP/1."):
                info["service"] = "http"

    if not info["service"]:
        try:
            info["service"] = socket.getservbyport(port, "tcp")
        except OSError:
            info["service"] = "unknown"

    # keep a short, printable first line for the report
    first = banner.strip().splitlines()[0] if banner.strip() else ""
    info["banner"] = "".join(c if c.isprintable() else "." for c in first)[:80]
    return info


def detect(host: str, port: int, timeout: float) -> dict:
    result = identify(port, grab_banner(host, port, max(timeout, 1.0)))
    result["port"] = port
    result["state"] = "open"
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="TCP connect port scanner with version detection")
    ap.add_argument("host", help="target hostname or IPv4 address")
    ap.add_argument("-p", "--ports", default="1-1024",
                    help="ports, e.g. 22,80,443 or 1-1024 (default 1-1024)")
    ap.add_argument("-t", "--timeout", type=float, default=1.0,
                    help="seconds to wait per port (default 1.0)")
    ap.add_argument("-w", "--workers", type=int, default=100,
                    help="concurrent connections (default 100)")
    ap.add_argument("--no-version", action="store_true",
                    help="skip banner grabbing / version detection")
    ap.add_argument("-o", "--output", help="also write the text report to this file")
    ap.add_argument("--json", metavar="FILE", help="write results as JSON (input for cve_lookup.py)")
    args = ap.parse_args()

    try:
        ports = parse_ports(args.ports)
        ip = socket.gethostbyname(args.host)
    except (ValueError, socket.gaierror) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(f"Scanning {args.host} ({ip}), {len(ports)} ports, "
          f"timeout {args.timeout}s, {args.workers} workers")
    start = time.time()

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            scanned = pool.map(lambda p: (p, scan_port(ip, p, args.timeout)), ports)
            open_ports = [p for p, is_open in scanned if is_open]
            if args.no_version:
                results = []
                for p in open_ports:
                    try:
                        svc = socket.getservbyport(p, "tcp")
                    except OSError:
                        svc = "unknown"
                    results.append({"port": p, "state": "open", "service": svc,
                                    "product": "", "version": "", "banner": ""})
            else:
                results = list(pool.map(lambda p: detect(ip, p, args.timeout), open_ports))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130

    elapsed = time.time() - start
    lines = [f"{'PORT':<11}{'STATE':<7}{'SERVICE':<11}VERSION"]
    for r in results:
        ver = f"{r['product']} {r['version']}".strip() or (f"({r['banner']})" if r["banner"] else "")
        lines.append(f"{str(r['port']) + '/tcp':<11}{r['state']:<7}{r['service']:<11}{ver}")
    lines.append(f"\n{len(results)} open / {len(ports)} scanned in {elapsed:.2f}s")
    report = "\n".join(lines)
    print(report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"Target: {args.host} ({ip})\n{report}\n")
        print(f"Saved to {args.output}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"target": args.host, "ip": ip,
                       "scanned_at": datetime.now(timezone.utc).isoformat(),
                       "ports": results}, f, indent=2)
        print(f"JSON saved to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
