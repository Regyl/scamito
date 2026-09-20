from dataclasses import dataclass, field

@dataclass
class CveRecord:
    id: str
    severity: str
    score: float | None
    published: str
    description: str
    matched_cpes: list[str] = field(default_factory=list)

@dataclass
class ScannedPortRecord:
    port: int
    product: str
    version: str
    cve: list[CveRecord] = field(default_factory=list)

@dataclass
class ScannedIpRecord:
    ip: str
    hostnames: list = field(default_factory=list)
    ports: list[ScannedPortRecord] = field(default_factory=list)
