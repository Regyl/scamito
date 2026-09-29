"""Read-only queries for the scan inventory UI."""

import ipaddress
import os
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row

PAGE_SIZE = 50
SEVERITY_KEYS = ("critical", "high", "medium", "low", "unknown")

PG_CONN = {
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
    "dbname": os.getenv("POSTGRES_DB", "nmap"),
    "user": os.getenv("POSTGRES_USER", "postgres"),
    "password": os.getenv("POSTGRES_PASSWORD", "postgres"),
    "connect_timeout": 3,
    "options": "-c statement_timeout=15000",
}

_HOST_FROM = """
FROM (
    SELECT ip FROM nmap_hostnames
    UNION
    SELECT ip FROM e_ip_services
) h
LEFT JOIN (
    SELECT ip, array_agg(hostname::text ORDER BY hostname) AS hostnames
    FROM nmap_hostnames
    GROUP BY ip
) n ON n.ip = h.ip
LEFT JOIN (
    SELECT ip, COUNT(*)::int AS port_count
    FROM e_ip_services
    GROUP BY ip
) p ON p.ip = h.ip
LEFT JOIN (
    SELECT s.ip, MAX(c.score) AS max_score
    FROM e_ip_services s
    JOIN e_service_cve c
      ON c.product = s.product AND c.version = s.version
    GROUP BY s.ip
) sc ON sc.ip = h.ip
WHERE (
    %(q)s = ''
    OR position(lower(%(q)s) in lower(host(h.ip))) > 0
    OR EXISTS (
        SELECT 1
        FROM nmap_hostnames hn
        WHERE hn.ip = h.ip
          AND position(lower(%(q)s) in lower(hn.hostname)) > 0
    )
)
"""

_CVE_WHERE = """
WHERE (
    %(severity)s = ''
    OR (
        %(severity)s = 'unknown'
        AND lower(c.severity) NOT IN ('critical', 'high', 'medium', 'low')
    )
    OR lower(c.severity) = %(severity)s
)
AND (
    %(q)s = ''
    OR position(lower(%(q)s) in lower(c.product)) > 0
    OR position(lower(%(q)s) in lower(c.version)) > 0
    OR position(lower(%(q)s) in lower(c.cve_id)) > 0
)
"""


class DatabaseError(Exception):
    """Raised when the inventory database cannot be read."""


@contextmanager
def _cursor():
    try:
        conn = psycopg.connect(**PG_CONN, row_factory=dict_row)
    except psycopg.Error as exc:
        raise DatabaseError("Could not connect to Postgres.") from exc
    try:
        with conn.cursor() as cur:
            yield cur
    except psycopg.Error as exc:
        raise DatabaseError("Could not read the database.") from exc
    finally:
        conn.close()


def _page(page: int, total: int) -> tuple[int, int]:
    if total <= 0:
        return 1, 0
    last = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(max(page, 1), last)
    return page, (page - 1) * PAGE_SIZE


def _cve_row(row: dict) -> dict:
    return {
        "product": row["product"],
        "version": row["version"],
        "cve_id": row["cve_id"],
        "severity": row["severity"] or "",
        "score": row["score"],
        "published": row["published"] or "",
        "description": row["description"] or "",
        "matched_cpes": list(row["matched_cpes"] or []),
    }


def overview() -> dict:
    severity = {key: 0 for key in SEVERITY_KEYS}
    with _cursor() as cur:
        cur.execute(
            """
            SELECT
                (
                    SELECT COUNT(*)::int
                    FROM (
                        SELECT ip FROM nmap_hostnames
                        UNION
                        SELECT ip FROM e_ip_services
                    ) hosts
                ) AS hosts,
                (SELECT COUNT(*)::int FROM e_ip_services) AS services,
                (SELECT COUNT(*)::int FROM e_service_cve) AS cves
            """
        )
        counts = cur.fetchone()
        cur.execute(
            """
            SELECT
                CASE
                    WHEN lower(severity) IN ('critical', 'high', 'medium', 'low')
                        THEN lower(severity)
                    ELSE 'unknown'
                END AS bucket,
                COUNT(*)::int AS n
            FROM e_service_cve
            GROUP BY 1
            """
        )
        for row in cur.fetchall():
            severity[row["bucket"]] = row["n"]
    return {
        "hosts": counts["hosts"],
        "services": counts["services"],
        "cves": counts["cves"],
        "severity": severity,
    }


def list_hosts(q: str, page: int) -> dict:
    params = {"q": q.strip()}
    with _cursor() as cur:
        cur.execute(f"SELECT COUNT(*)::int AS total {_HOST_FROM}", params)
        total = cur.fetchone()["total"]
        page, offset = _page(page, total)
        cur.execute(
            f"""
            SELECT
                host(h.ip) AS ip,
                COALESCE(n.hostnames, ARRAY[]::text[]) AS hostnames,
                COALESCE(p.port_count, 0) AS port_count,
                sc.max_score
            {_HOST_FROM}
            ORDER BY sc.max_score DESC NULLS LAST, h.ip
            LIMIT %(limit)s OFFSET %(offset)s
            """,
            {**params, "limit": PAGE_SIZE, "offset": offset},
        )
        rows = [
            {
                "ip": row["ip"],
                "hostnames": list(row["hostnames"] or []),
                "port_count": row["port_count"],
                "max_score": row["max_score"],
            }
            for row in cur.fetchall()
        ]
    return {"rows": rows, "total": total, "page": page, "page_size": PAGE_SIZE}


def host_detail(ip: str) -> dict | None:
    try:
        normalized = str(ipaddress.ip_address(ip))
    except ValueError:
        return None
    with _cursor() as cur:
        cur.execute(
            """
            SELECT hostname
            FROM nmap_hostnames
            WHERE ip = %(ip)s::inet
            ORDER BY hostname
            """,
            {"ip": normalized},
        )
        hostnames = [row["hostname"] for row in cur.fetchall()]
        cur.execute(
            """
            SELECT port, product, version, confidence
            FROM e_ip_services
            WHERE ip = %(ip)s::inet
            ORDER BY port
            """,
            {"ip": normalized},
        )
        services = [dict(row) for row in cur.fetchall()]
        cur.execute(
            """
            SELECT
                product, version, cve_id, severity, score,
                published, description, matched_cpes
            FROM e_service_cve c
            WHERE EXISTS (
                SELECT 1
                FROM e_ip_services s
                WHERE s.ip = %(ip)s::inet
                  AND s.product = c.product
                  AND s.version = c.version
            )
            ORDER BY product, version, score DESC NULLS LAST, cve_id
            """,
            {"ip": normalized},
        )
        grouped: dict[tuple[str, str], list[dict]] = {}
        for row in cur.fetchall():
            grouped.setdefault((row["product"], row["version"]), []).append(_cve_row(row))
    if not hostnames and not services:
        return None
    for service in services:
        service["cves"] = grouped.get((service["product"], service["version"]), [])
    return {"ip": normalized, "hostnames": hostnames, "services": services}


def list_cves(q: str, severity: str, page: int) -> dict:
    params = {"q": q.strip(), "severity": severity}
    with _cursor() as cur:
        cur.execute(
            f"SELECT COUNT(*)::int AS total FROM e_service_cve c {_CVE_WHERE}",
            params,
        )
        total = cur.fetchone()["total"]
        page, offset = _page(page, total)
        cur.execute(
            f"""
            SELECT
                c.product,
                c.version,
                c.cve_id,
                c.severity,
                c.score,
                c.published,
                c.description,
                c.matched_cpes,
                COALESCE((
                    SELECT array_agg(DISTINCT host(s.ip) ORDER BY host(s.ip))
                    FROM e_ip_services s
                    WHERE s.product = c.product AND s.version = c.version
                ), ARRAY[]::text[]) AS hosts
            FROM e_service_cve c
            {_CVE_WHERE}
            ORDER BY c.score DESC NULLS LAST, c.cve_id, c.product, c.version
            LIMIT %(limit)s OFFSET %(offset)s
            """,
            {**params, "limit": PAGE_SIZE, "offset": offset},
        )
        rows = []
        for row in cur.fetchall():
            item = _cve_row(row)
            item["hosts"] = list(row["hosts"] or [])
            rows.append(item)
    return {"rows": rows, "total": total, "page": page, "page_size": PAGE_SIZE}
