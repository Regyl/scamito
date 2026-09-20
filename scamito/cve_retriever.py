"""List CVEs for a product:version pair via nvdlib (NVD API 2.0).

Examples:
    python cve_retriever.py MySQL:5.7.44-48
    python cve_retriever.py --cpe cpe:/a:mysql:mysql:5.7.44-48
"""

from __future__ import annotations

import logging
import os
import re
from functools import lru_cache
from typing import Any

import nvdlib

from model.ScannedIpRecord import CveRecord
from util.annotations import timed

log = logging.getLogger(__name__)

CPE_DISCOVERY_LIMIT = 2000

# nmap product names -> NVD (vendor, product) pairs
KNOWN_PRODUCTS: dict[str, list[tuple[str, str]]] = {
    "mysql": [("oracle", "mysql"), ("percona", "percona_server")],
    "postgresql": [("postgresql", "postgresql")],
    "postgresql db": [("postgresql", "postgresql")],
    "nginx": [("f5", "nginx"), ("igor_sysoev", "nginx")],
    "openssh": [("openbsd", "openssh")],
    "apache httpd": [("apache", "http_server")],
    "exim smtpd": [("exim", "exim")],
    "exim": [("exim", "exim")],
    "dovecot": [("dovecot", "dovecot")],
    "dovecot pop3d": [("dovecot", "dovecot")],
    "dovecot imapd": [("dovecot", "dovecot")],
    "dropbear sshd": [("dropbear", "dropbear_ssh")],
    "pure-ftpd": [("pureftpd", "pure-ftpd")],
    "vsftpd": [("vsftpd", "vsftpd")],
    "openresty web app server": [("openresty", "openresty")],
    "proftpd or knftpd": [("proftpd", "proftpd")],
}

GENERIC_WORDS = {
    "db",
    "server",
    "smtpd",
    "httpd",
    "sshd",
    "daemon",
    "service",
    "web",
    "app",
}


def parse_spec(spec: str) -> tuple[str, str]:
    if ":" not in spec:
        raise ValueError('Expected "Product:version", e.g. MySQL:5.7.44-48')
    product, version = spec.split(":", 1)
    product, version = product.strip(), version.strip()
    if not product or not version:
        raise ValueError('Expected "Product:version", e.g. MySQL:5.7.44-48')
    return product, version


def version_candidates(version: str) -> list[str]:
    """NVD versions are usually the numeric core, not distro/vendor suffixes."""
    out: list[str] = []

    def add(value: str) -> None:
        value = value.strip()
        if value and value not in out:
            out.append(value)

    add(version)
    first = version.split()[0]
    add(first)

    match = re.search(r"\d+(?:\.\d+)+(?:[-+][\w.]+|[A-Za-z]\w*)?", first)
    if match:
        add(match.group(0))
    match = re.search(r"\d+(?:\.\d+)+", first)
    if match:
        add(match.group(0))
    return out


def cpe_to_2_3(cpe: str) -> str:
    raw = cpe.strip()
    if raw.startswith("cpe:2.3:"):
        parts = raw.split(":")
    elif raw.startswith("cpe:/"):
        parts = ["cpe", "2.3", *raw[5:].split(":")]
    else:
        raise ValueError(f"Unsupported CPE: {cpe}")
    while len(parts) < 13:
        parts.append("*")
    return ":".join(parts[:13])


def build_cpe(vendor: str, product: str, version: str) -> str:
    return cpe_to_2_3(f"cpe:2.3:a:{vendor}:{product}:{version}")


def _nvd_kwargs(**extra: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = dict(extra)
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        kwargs["key"] = api_key
        kwargs.setdefault("delay", 0.6)
    return kwargs


def product_keys(product: str) -> list[str]:
    raw = product.strip().lower()
    keys: list[str] = []

    def add(value: str) -> None:
        value = re.sub(r"[^a-z0-9]+", "_", value).strip("_")
        if value and value not in keys:
            keys.append(value)

    add(raw)
    words = re.findall(r"[a-z0-9]+", raw)
    core = [word for word in words if word not in GENERIC_WORDS]
    if core:
        add("_".join(core))
        add(core[0])
    if words:
        add(words[0])
    return keys


def _pairs_from_cpes(products: list[Any], expected: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    expected_n = expected.replace("-", "_")
    for item in products:
        name = getattr(item, "cpeName", "") or ""
        parts = name.split(":")
        if len(parts) < 5:
            continue
        vendor, prod = parts[3], parts[4]
        if prod.replace("-", "_") != expected_n:
            continue
        key = (vendor, prod)
        if key not in seen:
            seen.add(key)
            pairs.append(key)
    return pairs


def find_vendor_products(product: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(vendor: str, prod: str) -> None:
        key = (vendor.lower(), prod.lower())
        if key not in seen:
            seen.add(key)
            pairs.append(key)

    for vendor, prod in KNOWN_PRODUCTS.get(product.strip().lower(), []):
        add(vendor, prod)
    if pairs:
        return pairs[:5]

    for key in product_keys(product):
        try:
            items = nvdlib.searchCPE(
                **_nvd_kwargs(
                    cpeMatchString=f"cpe:2.3:a:*:{key}",
                    limit=CPE_DISCOVERY_LIMIT,
                )
            )
        except Exception as exc:
            log.error("NVD CPE search failed: %s", exc)
            continue
        for vendor, prod in _pairs_from_cpes(items, key):
            add(vendor, prod)
        if pairs:
            return pairs[:5]

    if not pairs:
        try:
            items = nvdlib.searchCPE(
                **_nvd_kwargs(
                    keywordSearch=product,
                    limit=CPE_DISCOVERY_LIMIT,
                )
            )
        except Exception as exc:
            log.error("NVD CPE keyword search failed: %s", exc)
            items = []
        for item in items:
            name = getattr(item, "cpeName", "") or ""
            parts = name.split(":")
            if len(parts) >= 5 and parts[2] == "a":
                add(parts[3], parts[4])
            if len(pairs) >= 5:
                break
    return pairs[:5]


def _severity_score(cve: Any) -> tuple[str, float | None]:
    score_info = getattr(cve, "score", None) or []
    if len(score_info) >= 3:
        _version, score, severity = score_info[0], score_info[1], score_info[2]
        if severity:
            return str(severity), float(score) if score is not None else None
    return "UNKNOWN", None


def _english_description(cve: Any) -> str:
    for item in getattr(cve, "descriptions", None) or []:
        lang = getattr(item, "lang", None)
        value = getattr(item, "value", None)
        if lang == "en" and value:
            return re.sub(r"\s+", " ", str(value)).strip()
    return ""


def cves_for_cpe(cpe: str) -> list[CveRecord]:
    log.info("Querying CPE", extra={"cpe": cpe})
    records: list[CveRecord] = []
    try:
        items = nvdlib.searchCVE(**_nvd_kwargs(cpeName=cpe, isVulnerable=True))
    except Exception as exc:
        log.error("NVD CVE search failed: %s", exc, extra={"cpe": cpe})
        return records

    for cve in items:
        cve_id = getattr(cve, "id", None)
        if not cve_id:
            continue
        severity, score = _severity_score(cve)
        published = str(getattr(cve, "published", "") or "")[:10]
        records.append(
            CveRecord(
                id=cve_id,
                severity=severity,
                score=score,
                published=published,
                description=_english_description(cve),
                matched_cpes=[cpe],
            )
        )
    return records


def merge_records(batches: list[list[CveRecord]]) -> list[CveRecord]:
    by_id: dict[str, CveRecord] = {}
    for batch in batches:
        for record in batch:
            existing = by_id.get(record.id)
            if existing is None:
                by_id[record.id] = record
                continue
            for cpe in record.matched_cpes:
                if cpe not in existing.matched_cpes:
                    existing.matched_cpes.append(cpe)
    return sorted(
        by_id.values(),
        key=lambda rec: (-(rec.score or -1.0), rec.id),
    )


@timed
@lru_cache(maxsize=None)
def lookup_cves(
    product: str,
    version: str,
) -> tuple[list[str], list[CveRecord]]:
    queried: list[str] = []
    batches: list[list[CveRecord]] = []

    if product and version:
        for vendor, prod in find_vendor_products(product):
            for ver in version_candidates(version):
                built = build_cpe(vendor, prod, ver)
                if built in queried:
                    continue
                queried.append(built)
                records = cves_for_cpe(built)
                batches.append(records)
                if records:
                    break

    return queried, merge_records(batches)
