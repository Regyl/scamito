"""Print hostnames/IPs from the Bank of Russia warning list API."""

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from scamito.util import annotations

BASE = "http://www.cbr.ru/warninglistapi"
PAGE_SIZE = 1000
WORKERS = 16
HEADERS = {"User-Agent": "Mozilla/5.0"}

log = logging.getLogger(__name__)

def get_json(path):
    req = Request(f"{BASE}{path}", headers=HEADERS)
    with urlopen(req, timeout=30) as resp:
        return json.load(resp)


def hosts_from_site(site) -> set:
    hosts = set()
    if not site:
        return hosts
    for part in re.split(r"[,;]+", site):
        part = part.strip()
        if not part:
            continue
        if "://" not in part:
            part = "http://" + part
        host = urlparse(part).hostname
        if host:
            hosts.add(host.lower())
    return hosts


def hosts_for_org(org_id) -> set:
    try:
        data = get_json(f"/DetailInfo?id={org_id}")
    except Exception:
        return set()
    hosts = set()
    for info in data.get("Info") or []:
        hosts |= hosts_from_site(info.get("site"))
    return hosts


def iter_org_ids():
    page = 0
    while True:
        rows = get_json(
            f"/Search?page={page}&dateFrom=2026-01-01&dateTo=2026-12-31"
        ).get("Data") or []
        if not rows:
            break
        yield from (row["id"] for row in rows if row.get("id") is not None)
        if len(rows) < PAGE_SIZE:
            break
        page += 1

@annotations.timed
def get_warning_hosts() -> set:
    log.info(f"Start looking for hosts")
    found = set()
    exclusions = {"max.ru", "www.avito.ru", "vk.ru", "vk.com", "ok.ru", "rutube.ru", "auto.drom.ru", "drom.ru", "avito.ru", "dzen.ru", "tenchat.ru"}
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for hosts in pool.map(hosts_for_org, iter_org_ids()):
            found |= hosts
    filtered = found - exclusions
    log.info(f"Found {len(hosts)} hosts")
    return filtered
