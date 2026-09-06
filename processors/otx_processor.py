from datetime import datetime, timezone

from models.intel import Intel
from models.ioc import IOC


class OTXProcessor:

    def process(self, raw_data: dict, queried_ioc: IOC) -> Intel:
        if not raw_data or not isinstance(raw_data, dict):
            raw_data = {}

        first_seen = self.extract_first_seen(raw_data)
        last_seen = self.extract_last_seen(raw_data)

        threat_actors = self.extract_threat_actors(raw_data)
        malware_families = self.extract_malware_families(raw_data)
        mitre_attack = self.extract_mitre_attack(raw_data)
        tags = self.extract_tags(raw_data)
        references = self.extract_references(raw_data)

        return Intel(
            source="OTX",

            queried_ioc=queried_ioc.ioc_value,
            queried_ioc_type=queried_ioc.ioc_type,

            first_seen=first_seen,
            last_seen=last_seen,

            lookup_status="SUCCESS",

            threat_actors=threat_actors,
            malware_families=malware_families,

            mitre_attack=mitre_attack,
            tags=tags,

            references=references,

            raw_data=raw_data
        )

    def get_pulses(self, raw_data: dict) -> list:
        pulse_info = raw_data.get("pulse_info") or {}
        if isinstance(pulse_info, dict):
            return pulse_info.get("pulses") or []
        return []

    def get_related(self, raw_data: dict) -> dict:
        pulse_info = raw_data.get("pulse_info") or {}
        if isinstance(pulse_info, dict):
            return pulse_info.get("related") or {}
        return {}

    def get_other_related(self, raw_data: dict) -> dict:
        related = self.get_related(raw_data)
        if isinstance(related, dict):
            return related.get("other") or {}
        return {}

    def extract_threat_actors(self, raw_data: dict) -> list[str]:
        related = self.get_other_related(raw_data)
        adversaries = related.get("adversary") or []
        return adversaries if isinstance(adversaries, list) else []

    def extract_malware_families(self, raw_data: dict) -> list[str]:
        related = self.get_other_related(raw_data)
        malware = related.get("malware_families") or []
        return malware if isinstance(malware, list) else []

    def extract_tags(self, raw_data: dict) -> list[str]:
        tags = set()
        for pulse in self.get_pulses(raw_data):
            if isinstance(pulse, dict):
                pulse_tags = pulse.get("tags") or []
                if isinstance(pulse_tags, list):
                    tags.update(pulse_tags)
        return sorted(tags)

    def extract_mitre_attack(self, raw_data: dict) -> list[str]:
        attack_ids = set()
        for pulse in self.get_pulses(raw_data):
            if isinstance(pulse, dict):
                attacks = pulse.get("attack_ids") or []
                if isinstance(attacks, list):
                    for attack in attacks:
                        if isinstance(attack, dict):
                            attack_id = attack.get("id")
                            if attack_id:
                                attack_ids.add(str(attack_id))
        return sorted(attack_ids)

    def extract_references(self, raw_data: dict) -> list[str]:
        references = set()
        for pulse in self.get_pulses(raw_data):
            if isinstance(pulse, dict):
                refs = pulse.get("references") or []
                if isinstance(refs, list):
                    references.update(refs)
        return sorted(references)

    def extract_first_seen(self, raw_data: dict):
        dates = []
        for pulse in self.get_pulses(raw_data):
            if isinstance(pulse, dict):
                created = pulse.get("created")
                if created:
                    try:
                        dt = datetime.fromisoformat(str(created))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        dates.append(dt)
                    except (ValueError, TypeError):
                        pass
        return min(dates) if dates else None

    def extract_last_seen(self, raw_data: dict):
        dates = []
        for pulse in self.get_pulses(raw_data):
            if isinstance(pulse, dict):
                modified = pulse.get("modified")
                if modified:
                    try:
                        dt = datetime.fromisoformat(str(modified))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        dates.append(dt)
                    except (ValueError, TypeError):
                        pass
        return max(dates) if dates else None

    def create_failed_intel(self, queried_ioc: IOC) -> Intel:
        return Intel(
            source="OTX",
            queried_ioc=queried_ioc.ioc_value,
            queried_ioc_type=queried_ioc.ioc_type,
            lookup_status="FAILED"
        )