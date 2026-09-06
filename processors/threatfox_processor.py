from models.intel import Intel
from models.ioc import IOC
from datetime import datetime, timezone


class ThreatFoxProcessor:

    def process(self, response: dict, queried_ioc: IOC):
        if not response or not isinstance(response, dict):
            response = {}

        data = response.get("data") or []
        if not isinstance(data, list):
            data = []

        return Intel(
            source="ThreatFox",
            queried_ioc=queried_ioc.ioc_value,
            queried_ioc_type=queried_ioc.ioc_type,

            first_seen=self._extract_first_seen(data),
            last_seen=self._extract_last_seen(data),

            lookup_status="SUCCESS",

            malware_families=self._extract_malware_families(data),
            tags=self._extract_tags(data),
            references=self._extract_references(data),

            raw_data=response
        )

    def _extract_malware_families(self, data: list[dict]):
        malware_families = []
        for record in data:
            if not isinstance(record, dict):
                continue
            malware = record.get("malware_printable")
            if malware and malware not in malware_families:
                malware_families.append(malware)
        return malware_families

    def _extract_tags(self, data: list[dict]):
        tags = []
        for record in data:
            if not isinstance(record, dict):
                continue
            for tag in record.get("tags") or []:
                if tag and tag not in tags:
                    tags.append(tag)
        return tags

    def _extract_references(self, data: list[dict]):
        references = []
        for record in data:
            if not isinstance(record, dict):
                continue
            reference = record.get("reference")
            if reference and reference not in references:
                references.append(reference)
        return references

    def _extract_first_seen(self, data: list[dict]):
        first_seen_dates = []
        for record in data:
            if not isinstance(record, dict):
                continue
            first_seen = record.get("first_seen")
            if first_seen:
                try:
                    dt_str = str(first_seen).replace(" UTC", "+00:00")
                    dt = datetime.fromisoformat(dt_str)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    first_seen_dates.append(dt)
                except (ValueError, TypeError):
                    pass
        if not first_seen_dates:
            return None
        return min(first_seen_dates)

    def _extract_last_seen(self, data: list[dict]):
        last_seen_dates = []
        for record in data:
            if not isinstance(record, dict):
                continue
            last_seen = record.get("last_seen")
            if last_seen:
                try:
                    dt_str = str(last_seen).replace(" UTC", "+00:00")
                    dt = datetime.fromisoformat(dt_str)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    last_seen_dates.append(dt)
                except (ValueError, TypeError):
                    pass
        if not last_seen_dates:
            return None
        return max(last_seen_dates)

    def create_failed_intel(self, queried_ioc: IOC) -> Intel:
        return Intel(
            source="ThreatFox",
            queried_ioc=queried_ioc.ioc_value,
            queried_ioc_type=queried_ioc.ioc_type,
            lookup_status="FAILED"
        )