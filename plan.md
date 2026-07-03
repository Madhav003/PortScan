# portscout — Project Plan

A single-file CLI port scanner: TCP connect scan (works everywhere) + optional Scapy SYN scan (root-only), with service/banner detection and table/JSON output.

## Core Goal

A CLI tool that scans a target for open ports, identifies the service running on each, and grabs a banner/version where possible. Two scan modes so it works with or without root.

## Feature Scope (2-day realistic)

### Day 1 — core engine
1. **TCP Connect scan** — no root needed, uses `socket.connect_ex()`. This is your baseline, always works.
2. **Threading/concurrency** — `ThreadPoolExecutor` so scanning 1000 ports doesn't take 1000×timeout. This is the "engineering" part that makes it more than a toy script.
3. **Port range parsing** — support `--ports 1-1000`, `--ports 22,80,443`, `--top-ports 100` (common ports list).
4. **Basic CLI** — `argparse` with target, port range, thread count, timeout flags.

### Day 2 — service ID + polish
5. **Service name lookup** — `socket.getservbyport()` for the standard name.
6. **Banner grabbing** — read what the service sends, or send a minimal probe (HTTP `HEAD /`) and read the response.
7. **SYN scan mode (Scapy, optional, root-only)** — `--syn` flag. Additive — don't block the project on it.
8. **Output formatting** — clean table to stdout, `--output results.json` for JSON export.
9. **README** — what it does, tech used, example run, screenshot/gif of output.

### Explicitly out of scope (stretch goals if time remains)
- OS fingerprinting (TTL/window-size heuristics)
- UDP scanning
- Rate limiting / firewall evasion tricks

## Tech Stack

- Python 3, stdlib `socket` + `concurrent.futures` (connect scan)
- `scapy` (SYN scan, optional import — tool should still run without it)
- `argparse` for CLI
- No external service DB needed — `socket.getservbyport` + a small manual dict for banner probes (HTTP, FTP, SMTP, SSH)

## File Structure

Single file: `portscout.py`

---

## Action Plan — Function by Function

### 1. `parse_ports(port_str)`
**Uses:** string parsing, no libraries.
**Does:** Converts the raw `--ports` argument into a clean list of integers to scan.

- Handles three input styles: `"1-1000"` (range), `"22,80,443"` (list), or a mix `"22,80,1000-2000"`.
- Split on commas first; for each chunk, check if it contains a `-`. If yes, split into start/end and `range(start, end+1)`. If no, it's a single port.
- Validate: ports must be 1–65535, dedupe with a `set()`, then `sorted()` at the end so output is predictable.
- Also handle a `--top-ports N` flag: a small hardcoded list of common ports, sliced to length N. Faster to demo than scanning all 65535.

### 2. `tcp_connect_scan(target, port, timeout)`
**Uses:** `socket` (stdlib).
**Does:** The actual "is this port open" check.

- Create a socket: `socket.socket(socket.AF_INET, socket.SOCK_STREAM)`.
- Set `sock.settimeout(timeout)` — critical, otherwise a filtered/dropped port hangs the whole scan.
- Call `result = sock.connect_ex((target, port))`. `connect_ex` returns an error code instead of raising an exception, so you don't need try/except for the common "connection refused" case.
- `result == 0` means the TCP handshake succeeded → port open. Anything else → closed/filtered.
- Return `(port, is_open)` and leave the socket open if it's open — reuse it for banner grabbing right after, don't close and reopen.

### 3. `scan_range_threaded(target, ports, max_threads, timeout)`
**Uses:** `concurrent.futures.ThreadPoolExecutor`.
**Does:** Turns a slow serial loop into a fast parallel scan.

- Sockets spend nearly all their time *waiting* on the network (I/O-bound) — threads work well here despite the GIL, since it releases during blocking I/O calls.
- `with ThreadPoolExecutor(max_workers=max_threads) as executor:` then `executor.submit(tcp_connect_scan, target, port, timeout)` for every port, collect futures in a dict `{future: port}`.
- Use `as_completed(futures)` to process results as they finish — lets you show a live progress counter instead of freezing until everything's done.
- Default `max_threads` around 100–200 is a reasonable balance.

### 4. `get_service_name(port)`
**Uses:** `socket.getservbyport(port, 'tcp')`.
**Does:** Cheap, offline lookup of the *expected* service name — e.g. port 22 → `"ssh"`. Wrap in try/except since unregistered/high ports raise `OSError`; fall back to `"unknown"`. This is just a label, not proof — that's what banner grabbing is for.

### 5. `grab_banner(sock, port, timeout)`
**Uses:** the already-open `socket` from step 2.
**Does:** Makes results feel real instead of just "open/closed."

- **Passive read** — many services (SSH, FTP, SMTP) send a greeting line the instant you connect. Just `sock.recv(1024)` with a short timeout and decode it. E.g. SSH gives you `SSH-2.0-OpenSSH_9.6` for free.
- **Active probe** — HTTP doesn't talk first, so for port 80/443/8080 send `sock.send(b"HEAD / HTTP/1.0\r\n\r\n")`, then read the response and parse the `Server:` header out of it.
- Wrap in try/except for `socket.timeout` — plenty of services won't respond, banner just becomes `None`.
- Always `sock.close()` at the end since it's the last thing that needs the connection.

### 6. `syn_scan(target, ports)` — optional, Scapy
**Uses:** `scapy.all` (`sr1`, `IP`, `TCP`).
**Does:** Sends a raw TCP SYN packet and inspects the response without completing the handshake (the "half-open" scan technique).

- Build packet: `IP(dst=target)/TCP(dport=port, flags="S")`.
- `sr1(packet, timeout=1, verbose=0)` sends it and waits for one response.
- Inspect response flags: `SA` (SYN-ACK) → port open, fire a `RST` back to tear down cleanly. `RA` (RST-ACK) → closed. No response → filtered.
- Requires raw socket privileges (root/sudo, or `CAP_NET_RAW` on Linux). Check `os.geteuid() == 0` upfront; if not available, print a clear message and fall back to connect scan rather than crashing.

### 7. `format_table(results)`
**Uses:** stdlib string formatting — no need for a table library.
**Does:** Prints an aligned table from the list of `{port, state, service, banner}` dicts, open ports only by default (with a `--show-closed` flag for verbose mode). Optional ANSI color for open ports (`\033[92m` green) — nice touch for a demo GIF.

### 8. `export_json(results, filepath)`
**Uses:** `json` (stdlib).
**Does:** `json.dump(results, f, indent=2)` — keep the output schema clean so it's reusable as input to a future project (e.g. your firewall simulator or IDS).

### 9. `main()`
**Does:** Wires it all together — parse args → parse ports → resolve target hostname to IP with `socket.gethostbyname()` → dispatch to `syn_scan` or `scan_range_threaded` based on `--syn` flag → for each open port, call `grab_banner` and `get_service_name` → pass everything to `format_table` and optionally `export_json`.

---

## Build/Test Order

1. `parse_ports` + `tcp_connect_scan` on a single port against `127.0.0.1` — get one true/false result working before anything else.
2. Wrap in the threaded scanner, test against `scanme.nmap.org` (Nmap's own project explicitly allows scanning this host).
3. Add service name + banner grabbing.
4. Add table/JSON output.
5. Scapy SYN scan last — most likely to hit environment issues (permissions, npcap on Windows, WSL raw socket quirks).