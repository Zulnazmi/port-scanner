# portscan

A small multithreaded TCP port scanner with service detection and banner grabbing, written in pure Python (standard library only, no dependencies).

> **Authorized use only.** Only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal. This project is for learning and legitimate security testing.

## Features
- Concurrent TCP connect scanning (configurable threads and timeout)
- Banner grabbing, with an HTTP `HEAD` probe on web ports
- Common service name mapping (SSH, HTTP, SMB, RDP, MySQL, ...)
- Flexible port specs: `22,80,443`, `1-1024`, or a mix
- Export results to JSON or CSV
- Unit tests using a local mock server

## Usage
Requires Python 3.8+.

```bash
python portscan.py <target> [-p PORTS] [-t TIMEOUT] [-T THREADS] [--no-banner] [-o FILE]
```

| Option | Description | Default |
|---|---|---|
| `-p, --ports` | Ports to scan (e.g. `22,80,1000-2000`) | `1-1024` |
| `-t, --timeout` | Per-port timeout in seconds | `1.0` |
| `-T, --threads` | Worker threads | `100` |
| `--no-banner` | Skip banner grabbing | off |
| `-o, --output` | Save results to `.json` or `.csv` | none |

### Example
Scanning my own machine:

```bash
python portscan.py 127.0.0.1 -p 1-1024 -o results.json
```

```
Scanning 127.0.0.1 (127.0.0.1) - 1024 ports, 100 threads

PORT    STATE   SERVICE       BANNER
135     open    msrpc
445     open    smb

Done: 2 open port(s) in 11.13s
Results saved to results.json
```

A safe public target for practice is `scanme.nmap.org` (see Nmap's usage policy).

## How it works
Each worker opens a full TCP connection (`connect()` scan) to one port. A completed handshake means the port is open; a refusal or timeout means closed or filtered. On open ports the scanner reads the first bytes the service sends (for example an SSH version string), and for HTTP ports sends a `HEAD` request to get the server header.

## Tests
```bash
python -m unittest -v
```

## Limitations and ideas
- TCP connect scans only (no SYN/UDP scanning, which would need raw sockets).
- No OS fingerprinting.
- Possible next steps: UDP scanning, IPv6, CIDR range support, rate limiting.

## License
MIT
