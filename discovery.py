import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Iterable

import requests

log = logging.getLogger(__name__)

CRT_SH = "https://crt.sh/"
UA = "KeyWatch/1.0 (security research)"


def _parse_dt(value: str) -> datetime | None:
    if not value:
        return None
    value = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fetch_certs(tld: str, timeout: int = 120) -> list[dict]:
    params = {"q": f"%.{tld}", "output": "json", "exclude": "expired"}
    for attempt in range(3):
        try:
            r = requests.get(
                CRT_SH, params=params, timeout=timeout,
                headers={"User-Agent": UA},
            )
            r.raise_for_status()
            data = r.json()
            if isinstance(data, list):
                return data
            log.warning("crt.sh non-list response for .%s", tld)
        except Exception as exc:
            log.warning("crt.sh .%s attempt %s failed: %s", tld, attempt + 1, exc)
            time.sleep(2 * (attempt + 1))
    return []


def extract_domains(certs: Iterable[dict], tld: str, cutoff: datetime) -> list[str]:
    """Return domains sorted newest-cert first, filtered by time window."""
    scored: dict[str, datetime] = {}
    suffix = f".{tld.lower()}"

    for cert in certs:
        issued = _parse_dt(cert.get("not_before", ""))
        if not issued or issued < cutoff:
            continue

        names = cert.get("name_value", "") or ""
        for line in names.splitlines():
            name = line.strip().lower()
            if not name or "*" in name:
                continue
            if name.endswith(suffix) and "." in name:
                prev = scored.get(name)
                if prev is None or issued > prev:
                    scored[name] = issued

    return [d for d, _ in sorted(scored.items(), key=lambda x: x[1], reverse=True)]


def discover_new_domains(
    tlds: list[str], hours: int, per_tld_limit: int = 2000
) -> list[str]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    all_domains: set[str] = set()

    for tld in tlds:
        log.info("Querying crt.sh for .%s (last %sh)", tld, hours)
        certs = fetch_certs(tld)
        domains = extract_domains(certs, tld, cutoff)
        log.info("  -> %s recent .%s domains", len(domains), tld)
        all_domains.update(domains[:per_tld_limit])
        time.sleep(1.5)  # be polite to crt.sh

    return sorted(all_domains)
