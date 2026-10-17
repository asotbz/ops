"""Prometheus exporter for nzbhydra2 indexer health.

nzbhydra2 has no metrics endpoint. Its external stats API (POST /api/stats/indexers,
API key in the JSON body) reports each indexer's state, backoff, hit counts and VIP expiry.
The API is read once per scrape; it does not search the indexers or spend their API hits.
"""

import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

URL = os.environ.get("NZBHYDRA_URL", "http://nzbhydra2:5076").rstrip("/") + "/api/stats/indexers"
API_KEY = os.environ["NZBHYDRA_API_KEY"]
PORT = int(os.environ.get("PORT", "9811"))
TIMEOUT = float(os.environ.get("TIMEOUT", "20"))

# DISABLED_SYSTEM_TEMPORARY: backing off after errors; DISABLED_SYSTEM: hydra gave up
# (e.g. bad credentials) until re-enabled by hand; DISABLED_USER: turned off on purpose.
STATES = ("ENABLED", "DISABLED_SYSTEM_TEMPORARY", "DISABLED_SYSTEM", "DISABLED_USER")

HELP = {
    "nzbhydra2_up": ("gauge", "1 if the stats API answered."),
    "nzbhydra2_scrape_duration_seconds": ("gauge", "Time taken to read the stats API."),
    "nzbhydra2_indexer_state": ("gauge", "1 for the indexer's current state."),
    "nzbhydra2_indexer_backoff_level": ("gauge", "Error backoff level; 0 when healthy."),
    "nzbhydra2_indexer_disabled_until_timestamp_seconds": ("gauge", "When a temporary disable ends."),
    "nzbhydra2_indexer_last_error_info": ("gauge", "The indexer's last error, as a label."),
    "nzbhydra2_indexer_api_hits": ("gauge", "API hits in the indexer's current limit window."),
    "nzbhydra2_indexer_api_hit_limit": ("gauge", "Daily API hit limit; absent when unlimited."),
    "nzbhydra2_indexer_download_hits": ("gauge", "Downloads in the indexer's current limit window."),
    "nzbhydra2_indexer_download_hit_limit": ("gauge", "Daily download limit; absent when unlimited."),
    "nzbhydra2_indexer_vip_expiry_timestamp_seconds": ("gauge", "VIP expiry; absent when Lifetime or unknown."),
}


def esc(v):
    return str(v).replace("\\", "\\\\").replace("\n", " ").replace('"', '\\"')


def timestamp(v):
    """hydra dates arrive as 'YYYY-MM-DD', ISO-8601 instants or epoch (s or ms)."""
    if v is None or v == "Lifetime":
        return None
    if isinstance(v, (int, float)):
        return v / 1000 if v > 1e11 else v
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()


def fetch():
    body = json.dumps({"apikey": API_KEY}).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.load(r)


def collect():
    samples = []
    start = time.monotonic()
    try:
        indexers = fetch()
        up = 1
    except Exception as e:  # report down, keep serving
        print(f"stats API failed: {type(e).__name__}", flush=True)
        indexers, up = [], 0
    samples.append(("nzbhydra2_up", {}, up))
    samples.append(("nzbhydra2_scrape_duration_seconds", {}, round(time.monotonic() - start, 3)))

    for i in indexers:
        name = {"indexer": i.get("indexer", "")}
        for s in STATES:
            samples.append(("nzbhydra2_indexer_state", {**name, "state": s}, int(i.get("state") == s)))
        samples.append(("nzbhydra2_indexer_backoff_level", name, i.get("level") or 0))
        if (t := timestamp(i.get("disabledUntil"))) is not None:
            samples.append(("nzbhydra2_indexer_disabled_until_timestamp_seconds", name, t))
        if i.get("lastError"):
            samples.append(("nzbhydra2_indexer_last_error_info", {**name, "error": i["lastError"][:200]}, 1))
        for key, metric in (("apiHits", "api_hits"), ("apiHitLimit", "api_hit_limit"),
                            ("downloadHits", "download_hits"), ("downloadHitLimit", "download_hit_limit")):
            if i.get(key) is not None:
                samples.append((f"nzbhydra2_indexer_{metric}", name, i[key]))
        if (t := timestamp(i.get("vipExpirationDate"))) is not None:
            samples.append(("nzbhydra2_indexer_vip_expiry_timestamp_seconds", name, t))

    out, seen = [], set()
    for metric, labels, value in samples:
        if metric not in seen:
            seen.add(metric)
            kind, text = HELP[metric]
            out += [f"# HELP {metric} {text}", f"# TYPE {metric} {kind}"]
        lbl = ",".join(f'{k}="{esc(v)}"' for k, v in labels.items())
        out.append(f"{metric}{{{lbl}}} {value}" if lbl else f"{metric} {value}")
    return "\n".join(out) + "\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        body = collect().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()
