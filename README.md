# Port Scanner + CVE Lookup

A TCP connect scanner in pure Python (`socket` + `ThreadPoolExecutor`) with service/version detection, plus a companion script that looks up known CVEs for what it finds. Built as part of my 12-month cybersecurity roadmap (Month 2).

> Only scan systems you own or have permission to test.

## Usage
```bash
# scan with version detection, save JSON
python3 scanner.py 127.0.0.1 -p 1-1024 --json scan.json

# look up CVEs for everything the scan identified
python3 cve_lookup.py --scan scan.json --min-score 7

# or look up a single product/version
python3 cve_lookup.py "Apache httpd" 2.4.49
```

Example scan output:
```
PORT       STATE  SERVICE    VERSION
9021/tcp   open   ftp        vsFTPd 3.0.3
9022/tcp   open   ssh        OpenSSH 8.2p1
9080/tcp   open   http       Apache httpd 2.4.49
```

### scanner.py flags
| Flag | Meaning | Default |
|---|---|---|
| `-p` | Ports: list and/or ranges | `1-1024` |
| `-t` | Timeout per port (s) | `1.0` |
| `-w` | Concurrent workers | `100` |
| `--no-version` | Skip banner grabbing | off |
| `-o` | Save text report | none |
| `--json` | Save results as JSON for `cve_lookup.py` | none |

### cve_lookup.py flags
| Flag | Meaning | Default |
|---|---|---|
| `--scan` | JSON file from `scanner.py --json` | none |
| `--min-score` | Hide CVEs below this CVSS score | `0` |
| `--top` | CVEs shown per service | `10` |
| `--json` | Save full results | none |

Set `NVD_API_KEY` (free from nvd.nist.gov) for much higher rate limits. Without a key the script waits about 6.5s between requests. Results are cached for 24h.

## How it works
- **Port scan:** `connect_ex()` attempts a full TCP handshake; return code 0 means open. No root needed, but it completes the handshake, so it is noisier in logs than Nmap's `-sS`.
- **Version detection:** for each open port it reads the service's greeting banner (SSH, FTP, SMTP, MySQL speak first). If the port stays quiet it sends an HTTP `HEAD` request (over TLS on 443/8443) and reads the `Server` header. Regex signatures map banners to product + version.
- **CVE lookup:** known products are mapped to a CPE name and queried against the NVD API 2.0, which is more accurate than keyword search. Unknown products fall back to keyword search. Results are sorted by CVSS and flagged `[KEV]` if CISA lists them as exploited in the wild.

## Limitations
- Banners can be hidden or spoofed, and distros backport fixes without changing the version string (e.g. Ubuntu's OpenSSH), so CVE matches are leads to verify, not findings.
- Fewer than 15 service signatures; unknown services just show their raw banner.
- IPv4 and TCP only.

## Roadmap
- More signatures and Nmap-style probes for quiet services
- UDP scanning
- Compare output against `nmap -sT -sV`
