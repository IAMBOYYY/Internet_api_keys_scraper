import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests

from discovery import discover_new_domains

log = logging.getLogger(__name__)

UA = "KeyWatch/1.0 (security research)"
PROBE_PATHS = [
    "/.env",
    "/config.json",
    "/api/config",
    "/debug",
    "/actuator/env",
    "/.git/config",
]
MAX_TEXT_BYTES = 200_000
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
RESULTS_PATH = os.path.join(DATA_DIR, "results.json")
SEEN_PATH = os.path.join(DATA_DIR, "seen_domains.json")


# ---------- storage ----------

def load_json(path: str, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_results() -> dict:
    return load_json(RESULTS_PATH, {
        "generated_at": None,
        "stats": {"scanned_total": 0, "findings_total": 0, "verified_total": 0},
        "findings": [],
    })


def save_results(findings: list[dict], scanned_this_run: int) -> None:
    prev = load_results()
    stats = prev.get("stats", {})
    stats["scanned_total"] = stats.get("scanned_total", 0) + scanned_this_run
    stats["findings_total"] = len(findings)
    stats["verified_total"] = sum(1 for f in findings if f.get("verified"))

    payload = {
        "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "stats": stats,
        "findings": sorted(findings, key=lambda f: f.get("found_at", ""), reverse=True),
    }
    save_json(RESULTS_PATH, payload)


def load_seen() -> set[str]:
    return set(load_json(SEEN_PATH, []))


def save_seen(seen: set[str]) -> None:
    # keep the most recent 20k entries to avoid unbounded growth
    save_json(SEEN_PATH, sorted(seen)[-20_000:])


# ---------- fetching ----------

def fetch_url(url: str, timeout: int = 10) -> str:
    try:
        r = requests.get(
            url, timeout=timeout, headers={"User-Agent": UA},
            allow_redirects=True,
        )
        if r.status_code == 200 and "text" in r.headers.get("content-type", ""):
            return r.text
    except Exception:
        pass
    return ""


def collect_domain_text(domain: str) -> tuple[str, str]:
    """Return (domain, combined_text) from HTML, JS, and common leak paths."""
    base = f"https://{domain}"
    html = fetch_url(base)
    if not html:
        html = fetch_url(f"http://{domain}")
    if not html:
        return domain, ""

    parts = [html]

    # external JS files
    for src in re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.I)[:15]:
        full = urljoin(base + "/", src)
        js = fetch_url(full)
        if js:
            parts.append(js)

    # common leak endpoints
    for path in PROBE_PATHS:
        body = fetch_url(urljoin(base + "/", path.lstrip("/")))
        if body:
            parts.append(body)

    text = "\n\n".join(parts)
    return domain, text[:MAX_TEXT_BYTES]


# ---------- trufflehog ----------

def _source_file(obj: dict) -> str:
    meta = obj.get("SourceMetadata", {})
    data = meta.get("Data", {})
    fs = data.get("Filesystem") or data.get("filesystem") or {}
    if isinstance(fs, dict):
        return fs.get("file") or fs.get("File") or ""
    return ""


def trufflehog_scan(batch: list[tuple[str, str]], tmp_root: str) -> list[dict]:
    paths: dict[str, str] = {}

    for domain, text in batch:
        if not text.strip():
            continue
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", domain)
        p = os.path.join(tmp_root, safe + ".txt")
        with open(p, "w", encoding="utf-8", errors="ignore") as f:
            f.write(text)
        paths[p] = domain

    if not paths:
        return []

    cmd = [
        "trufflehog", "filesystem", tmp_root,
        "--json", "--only-verified", "--no-update",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        source = _source_file(obj)
        domain = paths.get(source, "")
        raw = obj.get("Raw", "") or ""
        detector = obj.get("DetectorName", "Unknown")
        verified = bool(obj.get("Verified", False))

        findings.append({
            "domain": domain,
            "detector": detector,
            "verified": verified,
            "preview": raw[:10] + ("…" if len(raw) > 10 else ""),
            "raw_hash": hashlib.sha256(raw.encode()).hexdigest()[:16],
            "found_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        })

    return findings


# ---------- main ----------

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    tlds = [t.strip().lstrip(".") for t in os.getenv("TLDS", "com,dev,io,app,co").split(",")]
    hours = int(os.getenv("HOURS", "24"))
    max_domains = int(os.getenv("MAX_DOMAINS", "150"))

    seen = load_seen()
    discovered = discover_new_domains(tlds, hours)
    fresh = [d for d in discovered if d not in seen][:max_domains]

    log.info("Discovered %s domains, scanning %s fresh ones", len(discovered), len(fresh))

    findings: list[dict] = []
    batch: list[tuple[str, str]] = []

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(collect_domain_text, d): d for d in fresh}
        for fut in as_completed(futures):
            domain, text = fut.result()
            seen.add(domain)
            batch.append((domain, text))
            if len(batch) >= 25:
                with tempfile.TemporaryDirectory() as tmp:
                    findings.extend(trufflehog_scan(batch, tmp))
                batch = []

        if batch:
            with tempfile.TemporaryDirectory() as tmp:
                findings.extend(trufflehog_scan(batch, tmp))

    existing = load_results().get("findings", [])
    existing_hashes = {f.get("raw_hash") for f in existing if f.get("raw_hash")}
    new_findings = [f for f in findings if f["raw_hash"] not in existing_hashes]

    log.info("New findings: %s (verified: %s)", len(new_findings),
             sum(1 for f in new_findings if f["verified"]))

    save_results(existing + new_findings, len(fresh))
    save_seen(seen)


if __name__ == "__main__":
    main()
