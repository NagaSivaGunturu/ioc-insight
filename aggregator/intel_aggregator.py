from models.consolidated_intel import ConsolidatedIntel
from models.intel import Intel


class IntelAggregator:

    def aggregate(self, intel_list: list[Intel]) -> ConsolidatedIntel:

        if not intel_list:
            raise ValueError("No intelligence provided.")

        consolidated = ConsolidatedIntel(
            queried_ioc=intel_list[0].queried_ioc,
            queried_ioc_type=intel_list[0].queried_ioc_type
        )

        # Dates
        consolidated.first_seen = self._merge_first_seen(intel_list)
        consolidated.last_seen = self._merge_last_seen(intel_list)

        # Lists
        consolidated.threat_actors = self._merge_list(
            intel_list,
            "threat_actors"
        )

        consolidated.malware_families = self._merge_list(
            intel_list,
            "malware_families"
        )

        consolidated.campaigns = self._merge_list(
            intel_list,
            "campaigns"
        )

        consolidated.mitre_attack = self._merge_list(
            intel_list,
            "mitre_attack"
        )

        consolidated.tags = self._merge_list(
            intel_list,
            "tags"
        )

        consolidated.infrastructure_roles = self._merge_list(
            intel_list,
            "infrastructure_roles"
        )

        consolidated.targeted_sectors = self._merge_list(
            intel_list,
            "targeted_sectors"
        )

        consolidated.references = self._merge_list(
            intel_list,
            "references"
        )

        # Providers
        consolidated.providers = sorted(
            {
                intel.source
                for intel in intel_list
                if intel.lookup_status == "SUCCESS"
            }
        )

        # Failed Providers
        consolidated.failed_providers = sorted(
            {
                intel.source
                for intel in intel_list
                if intel.lookup_status == "FAILED"

            }
        )

        # Community Reports
        consolidated.community_reports = self._merge_community_reports(
            intel_list
        )

        return consolidated

    # ==========================================================
    # Merge Helpers
    # ==========================================================

    def _merge_list(
        self,
        intel_list: list[Intel],
        attribute: str
    ) -> list[str]:

        merged = []

        for intel in intel_list:
            merged.extend(
                getattr(intel, attribute)
            )

        return self._normalize_string_list(merged)

    def _merge_first_seen(
        self,
        intel_list: list[Intel]
    ):

        dates = [
            intel.first_seen
            for intel in intel_list
            if intel.first_seen is not None
        ]

        return min(dates) if dates else None

    def _merge_last_seen(
        self,
        intel_list: list[Intel]
    ):

        dates = [
            intel.last_seen
            for intel in intel_list
            if intel.last_seen is not None
        ]

        return max(dates) if dates else None

    def _merge_community_reports(
        self,
        intel_list: list[Intel]
    ) -> int:

        return sum(
            intel.community_reports or 0
            for intel in intel_list
        )

    # ==========================================================
    # Normalization Helpers
    # ==========================================================

    def _normalize_string_list(
        self,
        values: list[str]
    ) -> list[str]:

        normalized = {}

        for value in values:

            if value is None:
                continue

            value = value.strip()

            if not value:
                continue

            value = " ".join(value.split())

            key = value.casefold()

            #
            # Preserve the best-looking representation.
            #
            if key not in normalized:

                normalized[key] = value

            else:

                existing = normalized[key]

                #
                # Prefer Title Case or Mixed Case over ALL CAPS.
                #
                if existing.isupper() and not value.isupper():
                    normalized[key] = value
                elif not existing.isupper() and not value.isupper():
                    if value.istitle() and not existing.istitle():
                        normalized[key] = value

        return sorted(
            normalized.values(),
            key=str.casefold
        )
