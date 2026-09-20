import nmap

from util.annotations import timed

scanner = nmap.PortScanner()

@timed
def scan(hosts: str) -> dict:
    """
    :param hosts: hosts joined by whitespace. e.g: "abc.com dce.com"
    :return:
    """
    scan_result = scanner.scan(
        hosts,
        "1-10000",
        arguments="-sV --spoof-mac Apple -D RND:5 --min-parallelism 8 -T4 --resolve-all --unique --open"
    )
    return scan_result