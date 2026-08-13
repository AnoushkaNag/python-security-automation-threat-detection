"""VirusTotal API v3 IP-reputation enrichment for log-extracted public IPs.

Reads a plain-text log file, reuses Task 2's `extract_public_ips` from
log_enricher.py (instead of duplicating the regex/private-range filtering
logic), and queries the VirusTotal public API v3
(`https://www.virustotal.com/api/v3/ip_addresses/<ip>`) for each unique
public IP found. Task 2's own ip-api.com enrichment in log_enricher.py is
untouched -- this is a second, independent enrichment source.
"""

import argparse
import os
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

from log_enricher import extract_public_ips

VT_API_URL_TEMPLATE = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
REQUEST_TIMEOUT = 10


def get_api_key():
    """Load the VirusTotal API key from the VT_API_KEY environment variable.

    load_dotenv() first pulls VT_API_KEY out of a local .env file (if one
    exists) into the process environment, so a key set only in .env is
    picked up the same way a real environment variable would be. The key
    itself is never printed, logged, or otherwise included in any output.
    """
    load_dotenv()
    return os.environ.get("VT_API_KEY")


def query_virustotal(ip, api_key, timeout=REQUEST_TIMEOUT):
    """Query VirusTotal for one IP and return a normalized result dict.

    Every failure mode called out by the assignment -- missing/invalid
    key, rate limiting, 404, network errors, malformed JSON, unexpected
    response schema -- is caught here and turned into a result dict
    carrying an "error"/"message" pair instead of raising, so a single
    bad lookup never aborts the rest of the batch.
    """
    if not api_key:
        return {"error": "missing_api_key", "message": "VT_API_KEY is not set"}

    headers = {"x-apikey": api_key}
    url = VT_API_URL_TEMPLATE.format(ip=ip)

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        return {"error": "network_error", "message": f"Network error: {exc}"}

    if response.status_code == 401:
        return {"error": "invalid_api_key", "message": "VirusTotal rejected the API key (401 Unauthorized)"}
    if response.status_code == 429:
        return {"error": "rate_limited", "message": "VirusTotal rate limit exceeded (429 Too Many Requests)"}
    if response.status_code == 404:
        return {"error": "not_found", "message": f"No VirusTotal record found for {ip} (404 Not Found)"}
    if not response.ok:
        return {"error": "http_error", "message": f"VirusTotal returned HTTP {response.status_code}"}

    try:
        data = response.json()
    except ValueError:
        return {"error": "invalid_json", "message": "VirusTotal response was not valid JSON"}

    try:
        attributes = data["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
        malicious = stats["malicious"]
        harmless = stats["harmless"]
        last_analysis_ts = attributes["last_analysis_date"]
    except (KeyError, TypeError):
        return {"error": "unexpected_schema", "message": "Response is missing expected fields"}

    try:
        last_analysis_date = datetime.fromtimestamp(
            last_analysis_ts, tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OSError):
        last_analysis_date = "unknown"

    return {
        "malicious": malicious,
        "harmless": harmless,
        "last_analysis_date": last_analysis_date,
    }


def enrich_ips(ip_set, api_key):
    """Build the {ip: result_dict} mapping for every public IP found."""
    return {ip: query_virustotal(ip, api_key) for ip in sorted(ip_set)}


def print_summary(results):
    """Print a formatted IP | Malicious | Harmless | Last Analysis | Notes table."""
    header = f"{'IP':<16}{'Malicious':<11}{'Harmless':<10}{'Last Analysis (UTC)':<22}{'Notes'}"
    print(f"\nVirusTotal enrichment summary ({len(results)} public IP(s))")
    print(header)
    print("-" * len(header))
    if not results:
        print("No public IPs found in log.")
        return
    for ip, info in results.items():
        if "error" in info:
            print(f"{ip:<16}{'-':<11}{'-':<10}{'-':<22}{info['message']}")
        else:
            print(
                f"{ip:<16}{info['malicious']:<11}{info['harmless']:<10}"
                f"{info['last_analysis_date']:<22}"
            )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract public IPv4 addresses from a log file and "
        "enrich them via the VirusTotal API v3."
    )
    parser.add_argument("log_file", help="Path to a plain-text log file")
    return parser.parse_args()


def main():
    args = parse_args()

    with open(args.log_file, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    public_ips = extract_public_ips(lines)

    api_key = get_api_key()
    if not api_key:
        print(
            "VT_API_KEY is not set (checked the environment and a local .env "
            "file). VirusTotal lookups will be skipped for all IPs below."
        )

    results = enrich_ips(public_ips, api_key)
    print_summary(results)


if __name__ == "__main__":
    main()
