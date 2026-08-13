"""Multithreaded TCP port scanner with banner grabbing.

Scans a target IP over a given port range using concurrent threads, one
socket connection attempt per port. For every open port, a generic probe
is sent and any response returned by the service is captured as a banner.
Uses only the Python standard library (socket, threading, argparse) --
no nmap, subprocess, or third-party scanning libraries.

Intended for use only against hosts you are authorized to scan
(e.g. localhost or a private lab target you control).
"""

import argparse
import socket
import threading

# Generic probe sent to open ports in an attempt to elicit a banner.
# Many text-based protocols (SMTP, FTP, some HTTP servers, echo-style
# services, etc.) respond to a bare CRLF with an identifying line.
PROBE = b"\r\n"

# Number of bytes to read back when attempting to grab a banner.
RECV_SIZE = 1024


def scan_port(target_ip, port, timeout, results, results_lock):
    """Attempt a TCP connection to a single port and record the outcome.

    On success, sends PROBE and tries to read a banner. Any connection,
    timeout, or OS-level socket error is treated as "not open" and is
    swallowed so a single bad port never crashes the whole scan.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # A short timeout keeps closed/filtered ports from stalling the scan --
    # without it, a filtered port (no RST, no response) would make the
    # connect() call block indefinitely and the thread would hang forever.
    sock.settimeout(timeout)
    try:
        sock.connect((target_ip, port))

        banner = ""
        try:
            sock.sendall(PROBE)
            raw = sock.recv(RECV_SIZE)
            # Not every service replies in valid UTF-8 (or replies at all).
            # errors="replace" guarantees decode() can never raise on
            # arbitrary/binary bytes, so a malformed banner can't crash
            # the scanner -- it just shows up with replacement characters.
            banner = raw.decode("utf-8", errors="replace").strip()
        except (socket.timeout, OSError):
            # Port is open but the service didn't send anything back
            # within the timeout (or refused the probe write). That's
            # still a valid "open, no banner" result, not a failure.
            banner = ""

        # The results list is shared by every worker thread. Without a
        # lock, two threads could interleave their append() calls (or
        # race on the underlying list resize) and corrupt the list or
        # silently drop a result. The lock makes each append atomic.
        with results_lock:
            results.append((port, "open", banner))

    except (ConnectionRefusedError, socket.timeout, OSError):
        # Closed (connection refused) or filtered (timed out) port.
        # This is the expected, common case -- not an error condition --
        # so we simply skip recording it and move on.
        pass
    finally:
        sock.close()


def scan_targets(target_ip, start_port, end_port, timeout):
    """Spin up one thread per port in [start_port, end_port] and collect results."""
    results = []
    results_lock = threading.Lock()
    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(
            target=scan_port,
            args=(target_ip, port, timeout, results, results_lock),
            daemon=True,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    results.sort(key=lambda r: r[0])
    return results


def print_results(target_ip, results):
    """Print a formatted Port | State | Banner summary table for open ports."""
    print(f"\nScan results for {target_ip}")
    print(f"{'Port':<8}{'State':<8}{'Banner'}")
    print("-" * 50)
    if not results:
        print("No open ports found.")
        return
    for port, state, banner in results:
        display_banner = banner if banner else "(no banner)"
        print(f"{port:<8}{state:<8}{display_banner}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Multithreaded TCP port scanner with banner grabbing."
    )
    parser.add_argument("target_ip", help="Target IP address to scan")
    parser.add_argument("start_port", type=int, help="First port in range (inclusive)")
    parser.add_argument("end_port", type=int, help="Last port in range (inclusive)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket connection timeout in seconds (default: 1)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.start_port < 1 or args.end_port > 65535 or args.start_port > args.end_port:
        raise SystemExit("Invalid port range. Ports must be within 1-65535 and start <= end.")

    results = scan_targets(args.target_ip, args.start_port, args.end_port, args.timeout)
    print_results(args.target_ip, results)


if __name__ == "__main__":
    main()
