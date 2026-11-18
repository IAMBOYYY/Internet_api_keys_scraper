import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from queue import Queue, Empty
from urllib.parse import urljoin

import requests
import websockets
from flask import Flask, jsonify, render_template

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("keywatch")

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
RESULTS_PATH = os.path.join(DATA_DIR, "results.json")
TRUFFLEHOG = os.path.join(BASE_DIR, "bin", "trufflehog")
os.makedirs(DATA_DIR, exist_ok=True)

_lock = threading.Lock()
findings: list[dict] = []
seen_domains: set[str] = set()


def _load():
    if os.path.exists(RESULTS_PATH):
        try:
            with open(RESULTS_PATH, encoding="utf-8") as f:
                data = json.load(f)
            findings.extend(data.get("findings", []))
        except Exception:
            pass


def _save():
    with _lock:
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "stats": {
                "scanned_total": len(seen_domains),
                "findings_total": len(findings),
                "verified_total": sum(1 for f in findings if f.get("verified")),
            },
            "findings": sorted(findings, key=lambda x: x.get("found_at", ""), reverse=True),
        }
    tmp = RESULTS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    os.replace(tmp, RESULTS_PATH)


_load()

# ---------- scanning ----------

UA = "KeyWatch/1.0 (security research)"
PROBE_PATHS = ["/.env", "/config.json", "/api/config", "/debug", "/actuator/env", "/.git/config"]
MAX_TEXT = 200_000


def _fetch(url: str, timeout: int = 8) -> str:
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": UA}, allow_redirects=True)
        if r.status_code == 200 and "text" in r.headers.get("content-type", ""):
            return r.text
    except Exception:
        pass
    return ""


def _collect(domain: str) -> tuple[str, str]:
    base = f"https://{domain}"
    html = _fetch(base) or _fetch(f"http://{domain}")
    if not html:
        return domain, ""
    parts = [html]
    for src in re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.I)[:10]:
        js = _fetch(urljoin(base + "/", src))
        if js:
            parts.append(js)
    for p in PROBE_PATHS:
        body = _fetch(urljoin(base + "/", p.lstrip("/")))
        if body:
            parts.append(body)
    return domain, "\n\n".join(parts)[:MAX_TEXT]


def _trufflehog(batch: list[tuple[str, str]]) -> list[dict]:
    if not batch or not os.path.exists(TRUFFLEHOG):
        return []
    with tempfile.TemporaryDirectory() as tmp:
        paths: dict[str, str] = {}
        for domain, text in batch:
            if not text.strip():
                continue
            safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", domain)
            p = os.path.join(tmp, safe + ".txt")
            with open(p, "w", errors="ignore", encoding="utf-8") as f:
                f.write(text)
            paths[p] = domain

        if not paths:
            return []

        try:
            proc = subprocess.run(
                [TRUFFLEHOG, "filesystem", tmp, "--json", "--only-verified", "--no-update"],
                capture_output=True, text=True, timeout=180,
            )
        except Exception as exc:
            log.warning("trufflehog failed: %s", exc)
            return []

        out: list[dict] = []
        for line in proc.stdout.splitlines():
            try:
                obj = json.loads(line)
            except Exception:
                continue
            meta = obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
            src = meta.get("file", "") if isinstance(meta, dict) else ""
            domain = paths.get(src, "")
            raw = obj.get("Raw", "") or ""
            out.append({
                "domain": domain,
                "detector": obj.get("DetectorName", "Unknown"),
                "verified": bool(obj.get("Verified")),
                "preview": raw[:10] + ("…" if len(raw) > 10 else ""),
                "raw_hash": hashlib.sha256(raw.encode()).hexdigest()[:16],
                "found_at": datetime.now(timezone.utc).isoformat(),
            })
        return out


def _worker(q: Queue):
    while True:
        try:
            batch = q.get(timeout=5)
        except Empty:
            continue
        try:
            hits = _trufflehog(batch)
            if hits:
                with _lock:
                    existing = {f["raw_hash"] for f in findings}
                    new = [h for h in hits if h["raw_hash"] not in existing]
                    findings.extend(new)
                if new:
                    log.info("new findings: %d", len(new))
                    _save()
        except Exception:
            log.exception("worker error")
        finally:
            q.task_done()


scan_q: Queue = Queue()
for _ in range(2):
    threading.Thread(target=_worker, args=(scan_q,), daemon=True).start()

ALLOWED_TLDS = {t.strip().lstrip(".") for t in os.getenv("TLDS", "com,dev,io,app,co").split(",")}


def _on_domain(domain: str):
    domain = domain.strip().lower()
    if not domain or "*" in domain:
        return
    tld = domain.rsplit(".", 1)[-1]
    if tld not in ALLOWED_TLDS:
        return
    with _lock:
        if domain in seen_domains or len(seen_domains) >= 5000:
            return
        seen_domains.add(domain)
    d, text = _collect(domain)
    if text.strip():
        scan_q.put([(d, text)])


async def _certstream():
    url = "wss://api.certstream.dev/"
    backoff = 1
    while True:
        try:
            async with websockets.connect(url, ping_interval=30) as ws:
                log.info("CertStream connected")
                backoff = 1
                async for msg in ws:
                    try:
                        event = json.loads(msg)
                    except Exception:
                        continue
                    if event.get("message_type") != "dns_entries":
                        continue
                    for domain in event.get("data", []):
                        try:
                            _on_domain(domain)
                        except Exception:
                            pass
        except Exception as exc:
            log.warning("CertStream disconnected: %s (retry in %ss)", exc, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)


def _start_certstream():
    asyncio.run(_certstream())


threading.Thread(target=_start_certstream, daemon=True).start()

# ---------- Flask ----------


def _payload():
    with _lock:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "stats": {
                "scanned_total": len(seen_domains),
                "findings_total": len(findings),
                "verified_total": sum(1 for f in findings if f.get("verified")),
            },
            "findings": sorted(findings, key=lambda x: x.get("found_at", ""), reverse=True),
        }


@app.route("/")
def index():
    return render_template("index.html", data=_payload())


@app.route("/api/results")
def api_results():
    return jsonify(_payload())


@app.route("/healthz")
def healthz():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
