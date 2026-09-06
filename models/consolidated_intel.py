from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ConsolidatedIntel:

    queried_ioc: str
    queried_ioc_type: str

    providers: list[str] = field(default_factory=list)
    failed_providers: list[str] = field(default_factory=list)

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    threat_actors: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    campaigns: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)

    tags: list[str] = field(default_factory=list)

    infrastructure_roles: list[str] = field(default_factory=list)
    targeted_sectors: list[str] = field(default_factory=list)

    references: list[str] = field(default_factory=list)

    community_reports: int = 0