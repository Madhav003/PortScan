# portscout

A lightweight CLI port scanner written in Python. Scans a target for open ports, identifies the service running on each, and grabs a banner where possible. Built as a foundational network security tool — no external dependencies required for core scanning, with an optional raw SYN scan mode via Scapy.

## Status

🚧 Work in progress. Currently implemented:

- [x] `parse_ports` — parses `--ports` ranges/lists and `--top-ports N` shortcuts
- [x] `tcp_connect_scan` — single-port TCP connect scan
- [ ] `scan_range_threaded` — multithreaded scanning across a port range
- [ ] `get_service_name` — service name lookup
- [ ] `grab_banner` — banner/version grabbing
- [ ] `syn_scan` — optional raw SYN scan (Scapy, requires root)
- [ ] table + JSON output
- [ ] CLI (`argparse`)

## Why

Most "hello world" port scanners just check if a socket connects. This one aims to be closer to a real recon tool: threaded for speed, identifies services (not just open/closed), and supports both a connect scan (works anywhere, no privileges needed) and a SYN scan (faster, stealthier, root-only) — the same two techniques tools like Nmap are built around.

## Usage

```bash
# (coming soon once the CLI is wired up)
python portscout.py 192.168.1.1 --ports 1-1000
python portscout.py scanme.nmap.org --top-ports 20 --syn
python portscout.py 10.0.0.5 --ports 22,80,443 --output results.json
```

## Tech

- Python 3, stdlib `socket` + `concurrent.futures` for the core threaded connect scan
- [Scapy](https://scapy.net/) for optional raw SYN scanning
- No other dependencies

## Install

```bash
pip install -r requirements.txt
```

## Testing

Core scan logic is safe to test against `127.0.0.1` (localhost) or [`scanme.nmap.org`](https://nmap.org/book/testing.html), which Nmap's own project explicitly permits scanning for testing purposes. Do not scan hosts you don't own or have permission to test.

## License

MIT