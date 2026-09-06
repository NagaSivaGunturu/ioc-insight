from datetime import datetime, timezone

from models.consolidated_intel import ConsolidatedIntel
from models.intelligence_assessment import IntelligenceAssessment


class IntelAnalyzer:

    def analyze(
        self,
        intelligence: ConsolidatedIntel
    ):
        assessment = IntelligenceAssessment(
            intelligence=intelligence
        )

        assessment.ioc_intelligence_score = self.calculate_ioc_intelligence_score(
            intelligence,
            assessment
        )
        assessment.classification = self.calculate_classification(
            assessment.ioc_intelligence_score
        )
        assessment.summary = self.generate_summary(
            intelligence
        )

        return assessment

    def calculate_ioc_intelligence_score(
        self,
        intelligence: ConsolidatedIntel,
        assessment: IntelligenceAssessment
    ) -> int:
        score = 0
        active_threat_providers = set()

        # OTX findings
        if "OTX" in intelligence.providers and (
            intelligence.threat_actors or intelligence.malware_families or intelligence.mitre_attack
        ):
            active_threat_providers.add("OTX")
            score += 15
            assessment.reasons.append("Threat intelligence pulse(s) available from OTX")

        # ThreatFox findings
        if "ThreatFox" in intelligence.providers and (
            intelligence.malware_families or intelligence.tags or intelligence.references
        ):
            active_threat_providers.add("ThreatFox")
            score += 15
            assessment.reasons.append("Reported indicator(s) available from ThreatFox")

        # AbuseIPDB findings
        if intelligence.community_reports > 0:
            active_threat_providers.add("AbuseIPDB")
            score += 10
            assessment.reasons.append("Community abuse reports available from AbuseIPDB")

        # Threat Actor
        if intelligence.threat_actors:
            score += 20
            assessment.reasons.append("Known Threat Actor identified")

        # Malware
        if intelligence.malware_families:
            score += 15
            assessment.reasons.append("Known Malware Family identified")

        # Recent activity
        if intelligence.last_seen and len(active_threat_providers) > 0:
            last_seen = intelligence.last_seen
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - last_seen).days
            if age <= 90:
                score += 15
                assessment.reasons.append("Recent activity observed within 90 days")

        # Multiple providers with active threat findings
        if len(active_threat_providers) >= 2:
            score += 10
            assessment.reasons.append("IOC corroborated by multiple intelligence providers")

        return min(score, 100)

    def calculate_classification(self, score: int) -> str:
        if score >= 90:
            return "HIGH CONFIDENCE MALICIOUS"
        elif score >= 70:
            return "LIKELY MALICIOUS"
        elif score >= 40:
            return "SUSPICIOUS"
        elif score >10:
            return "LOW CONFIDENCE MALICIOUS"
        return "INSUFFICIENT INTELLIGENCE"

    def generate_summary(
        self,
        intelligence: ConsolidatedIntel
    ) -> str:
        sentences = []

        provider_count = (len(intelligence.providers)+len(intelligence.failed_providers))
        sentences.append(
            f"This {intelligence.queried_ioc_type} indicator has been queried across "
            f"{provider_count} threat intelligence source(s)."
        )

        associations = []
        if intelligence.threat_actors:
            associations.append("threat actor(s): " + ", ".join(intelligence.threat_actors))
        if intelligence.malware_families:
            associations.append("malware family(s): " + ", ".join(intelligence.malware_families))

        if associations:
            sentences.append("Associated with " + " and ".join(associations) + ".")

        if intelligence.community_reports > 0:
            sentences.append(f"The indicator has {intelligence.community_reports} community abuse report(s).")

        if intelligence.last_seen:
            last_seen = intelligence.last_seen
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - last_seen).days
            if age <= 90:
                sentences.append("Recent malicious activity has been observed within the last 90 days.")

        return " ".join(sentences)
