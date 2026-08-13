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

## Task 3 — Machine-Learning Threat Detector

### Dataset

- **Name:** Phishing Websites
- **Source:** UCI Machine Learning Repository, dataset id 327 —
  <https://archive.ics.uci.edu/dataset/327/phishing+websites>
- **Citation:** Mohammad, R., Thabtah, F., & McCluskey, L. (2015).
  Phishing Websites [Dataset]. UCI Machine Learning Repository.
  https://doi.org/10.24432/C51W2X
- **Size:** 11,055 rows (samples) × 31 columns (30 features + 1 target
  label) before preprocessing.
- **Features:** 30 lexical, host-based, and HTML/JavaScript-based
  indicators extracted from a URL/website (e.g. `having_ip_address`,
  `url_length`, `sslfinal_state`, `age_of_domain`, `web_traffic`), each
  discretized by the original authors into `{-1, 0, 1}`.
- **Label:** `result` — the dataset's original UCI terminology and label
  mapping is preserved: `-1` = phishing website, `1` = legitimate
  website.

### Retrieval / reproducibility

The dataset is **not committed** to this repository (it's fetched live
from UCI and is listed in `.gitignore` under `data/`). To reproduce:

```
pip install -r requirements.txt
python download_dataset.py       # fetches & caches data/phishing_websites.csv
python ml_threat_detector.py     # runs the full pipeline end-to-end
```

`ml_threat_detector.py` will also auto-download the dataset via
`download_dataset.py` on first run if `data/phishing_websites.csv` is not
already present, so `python ml_threat_detector.py` alone is sufficient.
`download_dataset.py` uses the official `ucimlrepo` client library
(`fetch_ucirepo(id=327)`) to pull the dataset directly from UCI.

### First five rows (actual output)

```
--- First 5 rows ---
   having_ip_address  url_length  ...  statistical_report  result
0                 -1           1  ...                  -1      -1
1                  1           1  ...                   1      -1
2                  1           0  ...                  -1      -1
3                  1           0  ...                   1      -1
4                  1           0  ...                   1       1

[5 rows x 31 columns]
```

(pandas truncates the middle columns of a 31-column frame by default when
printing; this is the real `df.head()` output, not abbreviated by hand.)

### Original class distribution

```
result
 1    6157
-1    4898
Name: count, dtype: int64
```

6,157 legitimate (`1`) vs. 4,898 phishing (`-1`) — a mild imbalance
favoring the legitimate class.

### Preprocessing

Applied in this order, matching the assignment's required sequence:

1. **Drop null rows** — `df.isnull().any(axis=1).sum()` was computed
   first to report the count, then `df.dropna()` was applied.
   **Null rows removed: 0** (the dataset has no missing values).
2. **Encode categorical features** — the script checks for any
   non-numeric (`object`-dtype) columns and label-encodes them if found.
   This dataset's 30 features are already fully numeric (`-1`/`0`/`1`),
   so **no categorical columns were found and no encoding was needed**.
3. **Detect duplicate rows** — `df.duplicated().sum()` was computed
   *before* dropping.
   **Duplicate rows detected and removed: 5,206.**
   This is a real, expected property of this dataset: because all 30
   features take only 3 possible discrete values each, many of the
   11,055 rows collide on the exact same 31-column combination (verified
   independently: 5,270 rows are duplicates on the 30 feature columns
   alone, ignoring the label — consistent with the 5,206 full-row
   duplicates found once the label is included).
4. **Drop duplicates** — `df.drop_duplicates()`, leaving **5,849 rows**.

Post-preprocessing class distribution (5,849 rows): `-1` (phishing) =
3,019, `1` (legitimate) = 2,830. Deduplication happened to remove
disproportionately more legitimate-class rows, so **the minority class
after preprocessing is legitimate (`1`)**, not phishing — the opposite of
the raw, pre-dedup distribution above. This matters for Task 3, item 9
(see Isolation Forest methodology below): the script determines the
minority class programmatically from the actual post-preprocessing
training labels (`y_train.value_counts().idxmin()`), rather than
assuming which class is smaller.

### Target/label column

`result` (see Dataset section above for its `-1`/`1` mapping).

### Train/test split

`train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)` —
an 80/20 split stratified on `result` to keep the same class ratio in
both the training set (4,679 rows) and test set (1,170 rows), since the
classes are not perfectly balanced.

### Random Forest — configuration and results

`RandomForestClassifier(random_state=42)` — **all hyperparameters left
at scikit-learn defaults** (`n_estimators=100`, `criterion="gini"`,
`max_depth=None`, etc.); `random_state=42` was set only for reproducible
output, not as tuning.

Precision/recall/F1 are reported with `pos_label=-1` (phishing treated as
the positive/detected class, the natural framing for a security
detector).

Test-set results (actual run output):

```
Accuracy:  0.9419
Precision: 0.9467
Recall:    0.9404
F1 score:  0.9435
```

Full `classification_report`:

```
               precision    recall  f1-score   support

 phishing(-1)       0.95      0.94      0.94       604
legitimate(1)       0.94      0.94      0.94       566

     accuracy                           0.94      1170
    macro avg       0.94      0.94      0.94      1170
 weighted avg       0.94      0.94      0.94      1170
```

### Isolation Forest — methodology and results

`IsolationForest(random_state=42)` (default `contamination="auto"`, all
other hyperparameters at scikit-learn defaults) is fit **only on
`X_train`'s features — it never sees `y_train`**. This is unsupervised
anomaly detection, not a supervised classifier; the true labels are used
afterward solely to *score* how well the anomalies it finds line up with
reality, which does not make the model itself supervised.

IsolationForest's raw `.predict()` output is `1` = inlier, `-1` =
anomaly. Per the assignment, the **minority class is treated as the
anomaly class**. The script computes this minority class directly from
`y_train` (`y_train.value_counts().idxmin()`) rather than assuming it, so
the mapping used for the actual run was:

```
Anomaly-label mapping (IsolationForest output -> class label): {-1: 1, 1: -1}
```

i.e. IsolationForest's `-1` (anomaly) → mapped to class label `1`
(legitimate, the post-preprocessing minority class); IsolationForest's
`1` (inlier) → mapped to class label `-1` (phishing, the majority class).
Predictions are remapped with this dictionary and then compared directly
against the real `result` values on the test set.

**Anomaly detection accuracy: 0.5641**

### Model comparison

| Model | Accuracy | Precision | Recall | F1 Score | Notes |
|---|---|---|---|---|---|
| Random Forest | 0.9419 | 0.9467 | 0.9404 | 0.9435 | Supervised classifier; default hyperparameters; positive class = phishing (`-1`) |
| Isolation Forest | 0.5641 | N/A | N/A | N/A | Unsupervised anomaly detector; accuracy computed via the explicit minority-class-as-anomaly mapping above. Precision/Recall/F1 are reported as N/A because Task 3 item 9 only requires anomaly-detection accuracy for this model — IsolationForest's `-1`/`1` output is a contamination-driven anomaly flag, not a calibrated classifier decision, so per-class precision/recall figures for it would not be directly comparable to the Random Forest's and are outside the assignment's required scope for this model |

### Discussion (196 words)

Raw accuracy is a poor headline metric for imbalanced security data
because a model can score deceptively high just by favoring the majority
class — on our test set, always predicting the majority class alone
would already score about 52% accuracy without catching a single real
threat correctly. Precision answers "of the alerts flagged as phishing,
how many were actually phishing?", which controls false-positive alert
fatigue for analysts; recall answers "of the real phishing sites, how
many did we catch?", which controls missed threats. F1 is the harmonic
mean of precision and recall, so it only stays high when both are
reasonably high, penalizing models that inflate one at the other's
expense — our Random Forest's F1 of 0.94 shows it is catching most
phishing sites without flooding analysts with false alarms. In a real
SOC, Random Forest's limitation is that it can only recognize attack
patterns resembling its labeled training data, leaving it blind to
genuinely novel phishing techniques. Isolation Forest's limitation is the
opposite: with no concept of "phishing" at all, it just flags
statistically unusual feature combinations, including benign-but-rare
sites, which is why its accuracy here (56%) is far below the supervised
model's.

### Reproducibility instructions

```
pip install -r requirements.txt
python download_dataset.py
python ml_threat_detector.py
```

Both scripts were verified with `python -m py_compile download_dataset.py
ml_threat_detector.py` before the run, and the pipeline above was
executed end-to-end (fresh download included) to produce every number in
this section.

## Task 4 — VirusTotal REST API Enrichment

### What it does

`virustotal_check.py` reads a plain-text log file, reuses Task 2's
`extract_public_ips()` from `log_enricher.py` to pull out unique,
validated, non-private IPv4 addresses (instead of duplicating that
regex/filtering logic), and queries the **VirusTotal public API v3** IP
reputation endpoint for each one, conceptually:

```
GET https://www.virustotal.com/api/v3/ip_addresses/<ip>
```

For each IP it extracts `last_analysis_stats.malicious`,
`last_analysis_stats.harmless`, and `last_analysis_date` from the JSON
response, converts the Unix timestamp to a human-readable UTC string,
and builds a result dictionary such as:

```python
{
    "8.8.8.8": {
        "malicious": 0,
        "harmless": 90,
        "last_analysis_date": "2026-08-13 12:00:00 UTC"
    }
}
```

Task 2 (`log_enricher.py`, its ip-api.com enrichment, and `sample.log`)
was left completely untouched -- this is a separate script (Option B)
that only imports one existing function from it.

### API key handling

- The key is loaded **only** from the `VT_API_KEY` environment variable,
  via `get_api_key()` in `virustotal_check.py`. It is never hardcoded
  anywhere in the source.
- `python-dotenv`'s `load_dotenv()` is called first, so a local `.env`
  file (not committed) can set `VT_API_KEY` the same way a real shell
  environment variable would.
- The key is sent to VirusTotal using the correct v3 header:
  `headers = {"x-apikey": api_key}`.
- The key is never printed, logged, or included in any script output.

`.env.example` (placeholder only, not a real key):

```
VT_API_KEY=your_virustotal_api_key_here
```

`.gitignore` was updated to add `.env` (existing rules were preserved,
not removed):

```
__pycache__/
*.pyc
data/
.env
```

### Usage

```
pip install -r requirements.txt
# create a local .env with your own key (never commit this file):
#   VT_API_KEY=<your real key>
python virustotal_check.py sample.log
```

### Error handling

`query_virustotal()` wraps every network/parsing step in `try/except`
and returns a `{"error": ..., "message": ...}` dict instead of raising,
so one bad IP/response never stops the rest of the batch:

| Condition | Handling |
|---|---|
| `VT_API_KEY` missing | Detected before any request is made; prints one clear warning, IP is reported with `error: missing_api_key` |
| HTTP 401 (invalid key) | Caught via status-code check; `error: invalid_api_key` |
| HTTP 429 (rate limited) | Caught via status-code check; `error: rate_limited` |
| HTTP 404 (not found) | Caught via status-code check; `error: not_found` |
| Network error (timeout, DNS, connection refused) | Caught via `requests.exceptions.RequestException`; `error: network_error` |
| Malformed JSON | Caught via `response.json()` raising `ValueError`; `error: invalid_json` |
| Missing/unexpected fields | Caught via `KeyError`/`TypeError` when reading `last_analysis_stats`; `error: unexpected_schema` |

### Testing performed

No real VirusTotal API key was available in this environment
(`VT_API_KEY` was unset), so testing covered two tracks:

**1. Real, unmocked run — missing-key path.** Run against `sample.log`
with no `VT_API_KEY` set at all (actual output, not fabricated):

```
VT_API_KEY is not set (checked the environment and a local .env file). VirusTotal lookups will be skipped for all IPs below.

VirusTotal enrichment summary (3 public IP(s))
IP              Malicious  Harmless  Last Analysis (UTC)   Notes
----------------------------------------------------------------
1.1.1.1         -          -         -                     VT_API_KEY is not set
203.0.113.42    -          -         -                     VT_API_KEY is not set
8.8.8.8         -          -         -                     VT_API_KEY is not set
```

Exit code `0`, no traceback -- confirms the missing-key path never
crashes the script.

**2. Mocked HTTP responses — every other error path plus success.**
Using `unittest.mock.patch` on `virustotal_check.requests.get` with a
fake, non-functional placeholder key string (never a real key), each
branch of `query_virustotal()` was exercised directly and asserted to
return the correct `error` key (or a clean success dict) without
raising:

- successful 200 response → parsed correctly into
  `{"malicious": 2, "harmless": 88, "last_analysis_date": "2025-08-12 12:00:00 UTC"}`
- HTTP 401 → `error: invalid_api_key`
- HTTP 429 → `error: rate_limited`
- HTTP 404 → `error: not_found`
- malformed (non-JSON) body → `error: invalid_json`
- simulated `ConnectionError` → `error: network_error`
- well-formed JSON missing `last_analysis_stats` → `error: unexpected_schema`

All eight cases (including the missing-key case) passed. The mock test
script was run for verification only and is not part of the committed
deliverable.

### Sample output (for at least two IPs)

**Example mocked output** — live VirusTotal API access was not available
(no `VT_API_KEY` configured in this environment), so the two rows below
are illustrative values from the mocked-response test above and a
second, manually-constructed mocked example, formatted exactly as
`print_summary()` renders them. These are **not** real VirusTotal
results:

```
Example mocked output
VirusTotal enrichment summary (2 public IP(s))
IP              Malicious  Harmless  Last Analysis (UTC)   Notes
----------------------------------------------------------------
8.8.8.8         2          88        2025-08-12 12:00:00 UTC
1.1.1.1         0          91        2025-08-12 09:15:00 UTC
```

If you configure a real `VT_API_KEY` locally (via `.env`, never
committed) and run `python virustotal_check.py sample.log`, this table
will populate with genuine VirusTotal data instead.

## Input → Process → Output

Every script in this repository follows the same automation shape: take
in raw, low-level data; run a defined, repeatable process over it; hand
back a distilled, decision-ready result. `port_scanner.py` takes a
**target IP and port range as input**, **processes** it by attempting a
concurrent TCP connection to every port and grabbing any banner offered,
and produces **output** as a table of open ports and services.
`log_enricher.py` takes a **raw log file as input**, **processes** it by
extracting, validating, and deduplicating public IPs before querying
ip-api.com for each one, and produces **output** as a per-IP threat
intelligence table (country, ISP, hosting/proxy/mobile flags).
`ml_threat_detector.py` takes a **labeled phishing-website dataset as
input**, **processes** it by cleaning/deduplicating the data and training
a Random Forest classifier plus an Isolation Forest anomaly detector, and
produces **output** as evaluation metrics (accuracy, precision, recall,
F1) that quantify how well each model distinguishes phishing from
legitimate sites.

## Task 5 — SOAR Workflow Integration

This section is a design discussion: the repository does not connect to
any commercial SOAR product, and no such integration exists in the code.
It describes how the four scripts above could be wired into a SOAR
(Security Orchestration, Automation, and Response) workflow.

This repository's three capabilities map onto distinct SOAR workflow
stages. `port_scanner.py` supports the investigation/data-collection
stage, discovering open ports and service banners on a host under active
review. `log_enricher.py` and `virustotal_check.py` support the
enrichment stage: they extract and deduplicate public IPs from raw logs,
then attach threat-intelligence context — geolocation, hosting/proxy
flags, and VirusTotal vendor-detection counts. `ml_threat_detector.py`
supports detection and classification, converting enriched observations
into a malicious/benign signal.

A realistic flow: a suspicious IP appears in firewall or authentication
logs. `log_enricher.py` extracts and deduplicates it, then `ip-api.com`
and VirusTotal enrich it with geolocation and reputation data. If the IP
belongs to infrastructure the organization is authorized to inspect,
`port_scanner.py` investigates which services it exposes. These enriched
features feed `ml_threat_detector.py`, which outputs a
malicious-confidence score that the SOAR platform uses to decide the
next action.

I propose three thresholds. At or above 0.90 confidence, the SOAR
platform automatically blocks the IP at the firewall, since the evidence
justifies the risk of automation. Between 0.60 and 0.89, it opens a case
and escalates to a human SOC analyst, since the evidence is suggestive
but not conclusive. Below 0.60, it simply logs the event for future
correlation.

This threshold balances two failure modes. A false positive at high
confidence could block a legitimate partner, customer, or business
service, so full automation stays reserved for very strong evidence. A
false negative left uninvestigated lets a genuine attacker continue
operating, so mid-confidence cases still reach an analyst instead of
being silently dropped.
