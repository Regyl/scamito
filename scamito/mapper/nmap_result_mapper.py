import logging

log = logging.getLogger(__name__)

def _hostnames(address: dict) -> list[str]:
    names = []
    seen = set()
    for item in address.get("hostnames") or []:
        name = item.get("name") if isinstance(item, dict) else item
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def _text(value) -> str | None:
    if value is None:
        return None
    if value == "":
        return None
    return str(value).strip()


def _confidence(value) -> int:
    if value is None or value == "":
        return 0
    try:
        return int(value)
    except (TypeError, ValueError) as e:
        log.exception(f"Failed to convert confidence value to int: {str(e)}")
        return 0


def rows_from_scan(
    scan_result: dict,
) -> tuple[list[tuple[str, str]], list[tuple[str, int, str, str, int]]]:
    hostname_rows = []
    service_rows = []
    scan = (scan_result or {}).get("scan") or {}
    for ip, address in scan.items():
        address = address or {}
        for hostname in _hostnames(address):
            hostname_rows.append((ip, hostname))
        ports = address.get("tcp") or {}
        for port, val in ports.items():
            if not isinstance(val, dict):
                continue
            if val.get("state") not in (None, "open"):
                continue
            service_rows.append(
                (
                    ip,
                    int(port),
                    _text(val.get("product")),
                    _text(val.get("version")),
                    _confidence(val.get("conf")),
                )
            )
    return hostname_rows, service_rows