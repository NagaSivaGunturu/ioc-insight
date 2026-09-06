from dataclasses import dataclass, field
from typing import Any
from datetime import datetime


@dataclass
class Intel:
    source: str

    queried_ioc: str
    queried_ioc_type: str

    lookup_status: str = "SUCCESS"

    first_seen: datetime  | None = None
    last_seen: datetime | None = None

    threat_actors: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    campaigns: list[str] = field(default_factory=list)

    mitre_attack: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    infrastructure_roles: list[str] = field(default_factory=list)
    targeted_sectors: list[str] = field(default_factory=list)

    references: list[str] = field(default_factory=list)

    #provider_confidence: int | None = None  --> mostly not required, as we are not using this field in any of the renderers, and also not using it in the assessment.py file. So, we can remove it for now.
    community_reports: int | None = None

    raw_data: dict[str, Any] = field(default_factory=dict, repr=False)