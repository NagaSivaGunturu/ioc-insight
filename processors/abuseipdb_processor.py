from datetime import datetime, timezone

from models.intel import Intel
from models.ioc import IOC

ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted"
}


class AbuseIPDBProcessor:

    def process(self, response: dict, queried_ioc: IOC):
        if not response or not isinstance(response, dict):
            response = {}

        data = response.get("data") or {}
        if not isinstance(data, dict):
            data = {}

        return Intel(
            source="AbuseIPDB",
            queried_ioc=queried_ioc.ioc_value,
            queried_ioc_type=queried_ioc.ioc_type,

            lookup_status="SUCCESS",

            last_seen=self.extract_last_seen(data),
            tags=self.extract_tags(data),
            community_reports=self.extract_community_reports(data),

            raw_data=response
        )

    def extract_last_seen(self, data: dict):
        last_reported_at = data.get("lastReportedAt")
        if not last_reported_at:
            return None
        try:
            dt_str = str(last_reported_at).replace("Z", "+00:00")
            dt = datetime.fromisoformat(dt_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            return None

    def extract_tags(self, data: dict):
        tags = set()
        reports = data.get("reports") or []
        for report in reports:
            if not isinstance(report, dict):
                continue
            for category in report.get("categories") or []:
                tag = ABUSEIPDB_CATEGORIES.get(category)
                if tag:
                    tags.add(tag)
        return sorted(tags)

    def extract_community_reports(self, data: dict):
        return data.get("totalReports") or 0

    def create_failed_intel(self, queried_ioc: IOC) -> Intel:
        return Intel(
            source="AbuseIPDB",
            queried_ioc=queried_ioc.ioc_value,
            queried_ioc_type=queried_ioc.ioc_type,
            lookup_status="FAILED"
        )