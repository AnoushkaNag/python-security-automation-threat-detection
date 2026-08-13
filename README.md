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
