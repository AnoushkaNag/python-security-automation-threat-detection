# Python Security Automation and AI/ML-Driven Threat Detection

## Task 1 — Multithreaded Port Scanner

### Purpose

`port_scanner.py` scans a target host over a specified TCP port range to
identify open ports and, where possible, grab a service banner from each
open port. It is built entirely from the Python standard library (`socket`,
`threading`, `argparse`) with no `nmap`, `subprocess`, or third-party
scanning dependencies.

### Requirements

- Python 3.x standard library only.
- Authorization to scan the target. Only scan hosts you own or are
  explicitly permitted to test (e.g. `localhost` or a private lab host).

### Usage

```
python port_scanner.py <target_ip> <start_port> <end_port> [--timeout SECONDS]
```

- `target_ip` — IP address to scan.
- `start_port` / `end_port` — inclusive port range (1-65535).
- `--timeout` — per-connection socket timeout in seconds (default: `1`).

Example:

```
python port_scanner.py 127.0.0.1 9995 10005 --timeout 1
```

### How it works

**Socket-based scanning.** For each port in the range, the scanner opens a
plain TCP `socket.socket(AF_INET, SOCK_STREAM)` and attempts
`connect((target_ip, port))`. A successful connect means the port is open;
`ConnectionRefusedError` means the port is closed; a timeout means the
port is filtered (or the host is unreachable on that port). All three
outcomes are handled explicitly so the scanner never crashes on a single
port's result.

**Threading.** A separate `threading.Thread` is spawned for each port in
the requested range, so all connection attempts run concurrently instead
of sequentially. This makes scanning a large port range dramatically
faster than a single-threaded loop, since most of the time per port is
spent waiting on I/O (connect/timeout), not on CPU work — an ideal fit for
Python threads despite the GIL. The main thread `join()`s every worker
before printing results, so the summary table is only built once every
port has finished.

**Shared-results lock.** All worker threads append their findings to one
shared `results` list. Python list appends are not guaranteed atomic
across threads doing compound operations, and concurrent, un-synchronized
writers can interleave in ways that corrupt the list or drop entries. A
single `threading.Lock()` (`results_lock`) is acquired with a `with`
block around each `append()` call, so only one thread mutates the list at
a time and no result is lost or corrupted.

**Timeouts and error handling.** Every socket has `settimeout(timeout)`
applied before connecting. Without a timeout, connecting to a filtered
port (one that silently drops packets instead of sending RST) would block
the thread indefinitely, since no response ever arrives. The default of 1
second keeps a full scan finishing in reasonable time while still giving
slow-but-open services a fair chance to respond. All connection and I/O
calls are wrapped in `try/except` blocks catching
`ConnectionRefusedError`, `socket.timeout`, and the general `OSError`, so
closed ports, filtered ports, and unexpected socket errors are all
treated as "not open" instead of raising an uncaught exception.

**Banner grabbing.** On a successful connect, the scanner sends a generic
`b"\r\n"` probe and calls `recv(1024)` to capture up to 1024 bytes of any
reply. Since a remote service can send back arbitrary — even
non-UTF-8 — bytes, the response is decoded with
`raw.decode("utf-8", errors="replace")` rather than a plain `.decode()`,
so malformed or binary data is turned into replacement characters instead
of raising a `UnicodeDecodeError` and crashing the scan. If a service
accepts the connection but sends nothing back within the timeout, the
port is still reported as open, just with an empty/`(no banner)` entry.

### Testing

Testing was performed only against `127.0.0.1` (localhost), which is
under the operator's own control. Since no pre-existing lab service was
present in the repository, a minimal temporary TCP echo/banner service
was started on `127.0.0.1:9999` purely for validation (it replies to any
connection with the banner `SSH-2.0-TestLabBanner\r\n`) and was shut down
immediately after the test. The scanned range `9995-10005` was chosen so
it contained exactly one open port (`9999`) surrounded by ten closed
ports, to demonstrate open-port detection, banner grabbing, and graceful
handling of closed ports in a single run.

Command used:

```
python port_scanner.py 127.0.0.1 9995 10005 --timeout 1
```

Actual output:

```
Scan results for 127.0.0.1
Port    State   Banner
--------------------------------------------------
9999    open    SSH-2.0-TestLabBanner
```

The run exited with status code `0` and produced no tracebacks. Ports
9995-9998 and 10000-10005 were closed (connection refused) on the local
machine and, as expected, do not appear in the table — confirming closed
ports are handled gracefully without crashing the scanner.

## Task 2 — Log Parser with Regex IP Extraction and Threat Intelligence Enrichment

### Purpose

`log_enricher.py` parses a plain-text firewall/syslog-style log file,
extracts every IPv4 address it can find with a regular expression, drops
private/internal addresses, deduplicates the remaining public IPs, and
enriches each one with geolocation and risk metadata (country, ISP,
hosting/proxy/mobile flags) from the free
[ip-api.com](http://ip-api.com/json/) API.

### Requirements

- Python 3.x standard library (`re`, `ipaddress`, `argparse`, `time`)
  plus the third-party `requests` library for the HTTP lookups.
- Outbound internet access to reach `http://ip-api.com`.
- A plain-text log file containing IPv4 addresses in dotted-decimal form.

### Usage

```
python log_enricher.py <log_file>
```

Example:

```
python log_enricher.py sample.log
```

### How it works

**Regex-based IP extraction.** `IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")`
scans every log line for four dot-separated groups of 1-3 digits. The
regex is intentionally permissive on digit range — it will match
`999.999.999.999` just as readily as `8.8.8.8` — because encoding a
strict 0-255 bound directly into a regex is fragile and hard to read.
Instead, every match is handed to `ipaddress.ip_address()`, which raises
`ValueError` on anything that isn't a real IPv4 address; those matches
are simply skipped. This keeps the extraction regex simple while still
guaranteeing every IP that survives is actually valid.

**Private-range filtering.** The assignment calls out three specific
private ranges to skip: `10.0.0.0/8`, `172.16.0.0/12` (i.e. `172.16.x.x`
through `172.31.x.x`), and `192.168.0.0/16`. Rather than checking these
with string prefixes (e.g. `ip.startswith("10.")`, which would also
wrongly match something like `101.2.3.4`), each candidate address is
parsed into an `ipaddress.ip_address` object and tested for membership in
the corresponding `ipaddress.ip_network` objects. This is the reliable,
standard-library-backed way to answer "is this address inside this
CIDR range?".

**Deduplication.** Surviving public IPs are added to a Python `set`
(`public_ips`), so an address that appears many times across a log (e.g.
repeated hits from the same scanner) is only enriched — and only counted
against the API rate limit — once.

**Threat intelligence enrichment.** For every unique public IP, the
script calls `requests.get("http://ip-api.com/json/<ip>")` and pulls
`country`, `isp`, `hosting`, `proxy`, and `mobile` out of the JSON
response into a dictionary keyed by IP address. ip-api.com's free tier
throttles at 45 requests/minute, so a `RATE_LIMIT_DELAY` (1.5s) pause is
inserted between lookups to stay well under that limit on logs with many
unique IPs. Network failures, timeouts, and API-reported failures
(`status != "success"` in the response body, e.g. for a reserved/
non-routable address ip-api can't geolocate) are all caught so a single
failed lookup falls back to `"unknown"`/`False` values instead of
crashing the whole enrichment run.

### Testing

Tested against a local `sample.log` file (included in this repo)
containing synthetic firewall-style lines with a deliberate mix of:
private IPs in all three skipped ranges (`192.168.1.15`, `10.0.0.1`,
`172.16.5.9`, `172.31.255.254`), a duplicated public IP (`8.8.8.8`,
appearing twice), a public IP (`1.1.1.1`), a syntactically-dotted but
out-of-range value (`999.999.999.999`), and a reserved/documentation
public-looking address (`203.0.113.42`). This only involves outbound
lookups to the public ip-api.com geolocation service — no scanning or
enrichment was performed against any address the operator does not
control or that isn't a standard public DNS/documentation IP.

Command used:

```
python log_enricher.py sample.log
```

Actual output:

```
Threat intelligence summary (3 public IP(s))
IP              Country             ISP                         Hosting  Proxy   Mobile
---------------------------------------------------------------------------------------
1.1.1.1         Australia           Cloudflare, Inc             False    False   False
8.8.8.8         United States       Google LLC                  False    False   False
203.0.113.42    United States       TEST-NET-3                  False    False   False
```

The run exited with status code `0` and produced no tracebacks. All four
private-range addresses and the invalid `999.999.999.999` match were
correctly excluded from the table, and the duplicated `8.8.8.8` was
enriched only once — confirming regex extraction, validation, private-IP
filtering, deduplication, and live API enrichment all worked as
required.
