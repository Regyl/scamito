"""Local PostgreSQL helpers for persisting nmap scan results."""

import os

import psycopg

from scamito.mapper import nmap_result_mapper
from scamito.model.ScannedIpRecord import CveRecord
from scamito.util.annotations import timed

PG_CONN = {
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
    "dbname": os.getenv("POSTGRES_DB", "nmap"),
    "user": os.getenv("POSTGRES_USER", "postgres"),
    "password": os.getenv("POSTGRES_PASSWORD", "postgres"),
}

INSERT_HOSTNAME_SQL = """
INSERT INTO nmap_hostnames (ip, hostname)
VALUES (%s, %s)
ON CONFLICT (ip, hostname) DO NOTHING;
"""

INSERT_SERVICE_SQL = """
INSERT INTO e_ip_services (ip, port, product, version, confidence)
VALUES (%s, %s, %s, %s, %s)
ON CONFLICT (ip, port) DO NOTHING;
"""

LIST_PROCESSED_HOSTNAMES_SQL = """
SELECT DISTINCT hostname
FROM nmap_hostnames;
"""

LIST_SERVICE_PRODUCTS_SQL = """
SELECT DISTINCT product, version
FROM e_ip_services
WHERE confidence = 10
  AND product <> ''
  AND version <> '';
"""

LIST_PROCESSED_CVE_PRODUCTS_SQL = """
SELECT DISTINCT product, version
FROM e_service_cve;
"""

INSERT_CVE_SQL = """
INSERT INTO e_service_cve (
    product, version, cve_id, severity, score, published, description, matched_cpes
)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (product, version, cve_id) DO NOTHING;
"""

@timed
def save_nmap_rows(scan_result: dict) -> tuple[int, int]:
    hostname_rows, service_rows = nmap_result_mapper.rows_from_scan(scan_result)
    with psycopg.connect(**PG_CONN) as conn:
        with conn.cursor() as cur:
            if hostname_rows:
                cur.executemany(INSERT_HOSTNAME_SQL, hostname_rows)
            if service_rows:
                cur.executemany(INSERT_SERVICE_SQL, service_rows)
        conn.commit()
    return len(hostname_rows), len(service_rows)


def list_processed_hostnames() -> set[str]:
    with psycopg.connect(**PG_CONN) as conn:
        with conn.cursor() as cur:
            cur.execute(LIST_PROCESSED_HOSTNAMES_SQL)
            return {hostname.lower() for (hostname,) in cur.fetchall() if hostname}


def list_service_products() -> list[tuple[str, str]]:
    with psycopg.connect(**PG_CONN) as conn:
        with conn.cursor() as cur:
            cur.execute(LIST_SERVICE_PRODUCTS_SQL)
            return [(product, version) for product, version in cur.fetchall()]


def list_processed_cve_products() -> set[tuple[str, str]]:
    with psycopg.connect(**PG_CONN) as conn:
        with conn.cursor() as cur:
            cur.execute(LIST_PROCESSED_CVE_PRODUCTS_SQL)
            return {(product, version) for product, version in cur.fetchall()}


@timed
def save_service_cves(product: str, version: str, records: list[CveRecord]) -> int:
    rows = [
        (
            product,
            version,
            rec.id,
            rec.severity or "",
            rec.score,
            rec.published or "",
            rec.description or "",
            rec.matched_cpes or [],
        )
        for rec in records
    ]
    if not rows:
        return 0
    with psycopg.connect(**PG_CONN) as conn:
        with conn.cursor() as cur:
            cur.executemany(INSERT_CVE_SQL, rows)
        conn.commit()
    return len(rows)
