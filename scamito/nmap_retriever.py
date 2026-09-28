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
        # "1-65535",
        arguments="-sV --spoof-mac Apple -D RND:5 -p- --open"
    )
    return scan_result