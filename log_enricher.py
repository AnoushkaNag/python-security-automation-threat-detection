"""Log parser with regex IP extraction and threat-intelligence enrichment.

Reads a plain-text firewall/syslog-style log file, extracts IPv4 addresses
with a regular expression, filters out private/internal addresses, and
enriches each unique public IP via the free ip-api.com geolocation API
(country, ISP, hosting/proxy/mobile flags). Uses only the standard library
plus the `requests` HTTP client -- no scanning or intrusive network access,
only a lookup against a public threat-intel style API.
"""

import argparse
import ipaddress
import re
import time

import requests

# Matches dotted-decimal IPv4 notation: four 1-3 digit groups separated by
# dots (e.g. 192.168.1.1, 8.8.8.8). This regex is deliberately permissive
# on digit *range* (it accepts "999") -- octet-range validity is checked
# afterwards with ipaddress.ip_address(), which is far less error-prone
# than trying to encode 0-255 bounds directly into the pattern.
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# The three private IPv4 ranges the assignment asks us to skip, expressed
# as real networks. Checking membership via the `ipaddress` module (rather
# than string-prefix matching like ip.startswith("10.")) correctly handles
# edge cases such as "10.5.5.5" vs. "101.2.3.4", which a naive prefix
# check could confuse.
PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

# ip-api.com's free tier throttles at 45 requests/minute per source IP.
# A short delay between lookups keeps a multi-IP log well under that
# limit instead of racing through requests and getting rate-limited.
RATE_LIMIT_DELAY = 1.5

API_URL_TEMPLATE = "http://ip-api.com/json/{ip}"


def extract_public_ips(lines):
    """Extract, validate, filter, and deduplicate public IPv4 addresses."""
    public_ips = set()
    for line in lines:
        for candidate in IP_REGEX.findall(line):
            try:
                ip_obj = ipaddress.ip_address(candidate)
            except ValueError:
                # Regex matches like "999.999.999.999" are syntactically
                # dotted-decimal but not valid IPv4 -- ip_address() rejects
                # them, so we simply skip the bogus match.
                continue
            if any(ip_obj in net for net in PRIVATE_NETWORKS):
                continue
            public_ips.add(str(ip_obj))
    return public_ips


def enrich_ip(ip, timeout=5):
    """Query ip-api.com for one IP and return the enrichment fields.

    Network failures, timeouts, and API-reported lookup failures are all
    caught here so that one bad/unreachable IP can't abort the whole
    enrichment run -- it just falls back to "unknown" values.
    """
    fallback = {
        "country": "unknown",
        "isp": "unknown",
        "hosting": False,
        "proxy": False,
        "mobile": False,
    }
    try:
        response = requests.get(API_URL_TEMPLATE.format(ip=ip), timeout=timeout)
        response.raise_for_status()
        data = response.json()
    except (requests.exceptions.RequestException, ValueError):
        return fallback

    if data.get("status") != "success":
        return fallback

    return {
        "country": data.get("country", "unknown"),
        "isp": data.get("isp", "unknown"),
        "hosting": data.get("hosting", False),
        "proxy": data.get("proxy", False),
        "mobile": data.get("mobile", False),
    }


def enrich_ips(ip_set):
    """Build the {ip: enrichment_dict} mapping for every public IP found."""
    enriched = {}
    for ip in sorted(ip_set, key=lambda addr: ipaddress.ip_address(addr)):
        enriched[ip] = enrich_ip(ip)
        time.sleep(RATE_LIMIT_DELAY)
    return enriched


def print_summary(enriched):
    """Print a formatted IP | Country | ISP | Hosting | Proxy | Mobile table."""
    header = f"{'IP':<16}{'Country':<20}{'ISP':<28}{'Hosting':<9}{'Proxy':<8}{'Mobile'}"
    print(f"\nThreat intelligence summary ({len(enriched)} public IP(s))")
    print(header)
    print("-" * len(header))
    if not enriched:
        print("No public IPs found in log.")
        return
    for ip, info in enriched.items():
        print(
            f"{ip:<16}{info['country']:<20}{info['isp']:<28}"
            f"{str(info['hosting']):<9}{str(info['proxy']):<8}{info['mobile']}"
        )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract public IPv4 addresses from a log file and "
        "enrich them via ip-api.com."
    )
    parser.add_argument("log_file", help="Path to a plain-text log file")
    return parser.parse_args()


def main():
    args = parse_args()

    with open(args.log_file, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    public_ips = extract_public_ips(lines)
    enriched = enrich_ips(public_ips)
    print_summary(enriched)


if __name__ == "__main__":
    main()
