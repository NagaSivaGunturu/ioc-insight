import os
import sys
import unittest
from datetime import datetime, timezone

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.config_loader import get_api_key, get_source_config
from models.ioc import IOC
from models.intel import Intel
from models.consolidated_intel import ConsolidatedIntel
from utils.ioc_validator import IOCValidator
from processors.threatfox_processor import ThreatFoxProcessor
from processors.abuseipdb_processor import AbuseIPDBProcessor
from processors.otx_processor import OTXProcessor
from aggregator.intel_aggregator import IntelAggregator
from analyzers.intel_analyzer import IntelAnalyzer
from clients.abuseipdb_client import AbuseIPDBClient
from clients.otx_client import OTXClient
from clients.threatfox_client import ThreatFoxClient


class TestIOCInsight(unittest.TestCase):

    def test_config_loader_env_override(self):
        os.environ["OTX_API_KEY"] = "test_env_otx_key"
        key = get_api_key("otx")
        self.assertEqual(key, "test_env_otx_key")
        del os.environ["OTX_API_KEY"]

    def test_ioc_validator(self):
        val, typ = IOCValidator.validate_and_normalize("8.8.8.8", "auto")
        self.assertEqual(val, "8.8.8.8")
        self.assertEqual(typ, "IPv4")

        val, typ = IOCValidator.validate_and_normalize("malicious.com", "auto")
        self.assertEqual(val, "malicious.com")
        self.assertEqual(typ, "domain")

        val, typ = IOCValidator.validate_and_normalize("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "auto")
        self.assertEqual(typ, "hash")

    def test_threatfox_processor_null_data(self):
        processor = ThreatFoxProcessor()
        ioc = IOC(ioc_type="IPv4", ioc_value="1.1.1.1")
        
        # Test null data response
        response = {"query_status": "no_result", "data": None}
        intel = processor.process(response, ioc)
        self.assertEqual(intel.source, "ThreatFox")
        self.assertEqual(intel.malware_families, [])
        self.assertIsNone(intel.first_seen)

    def test_abuseipdb_processor_null_data(self):
        processor = AbuseIPDBProcessor()
        ioc = IOC(ioc_type="IPv4", ioc_value="1.1.1.1")
        
        response = {"data": None}
        intel = processor.process(response, ioc)
        self.assertEqual(intel.source, "AbuseIPDB")
        self.assertEqual(intel.community_reports, 0)

    def test_analyzer_clean_ip_scoring(self):
        analyzer = IntelAnalyzer()
        
        # Simulated clean consolidated intel where zero threat pulses were found
        clean_intel = ConsolidatedIntel(
            queried_ioc="8.8.8.8",
            queried_ioc_type="IPv4",
            providers=["OTX", "ThreatFox", "AbuseIPDB"],
            first_seen=None,
            last_seen=None,
            threat_actors=[],
            malware_families=[],
            campaigns=[],
            mitre_attack=[],
            tags=[],
            references=[],
            community_reports=0
        )
        
        assessment = analyzer.analyze(clean_intel)
        self.assertEqual(assessment.ioc_intelligence_score, 0)
        self.assertEqual(assessment.classification, "LOW CONFIDENCE")

    def test_analyzer_malicious_ip_scoring(self):
        analyzer = IntelAnalyzer()
        
        # Simulated malicious consolidated intel
        malicious_intel = ConsolidatedIntel(
            queried_ioc="101.200.193.211",
            queried_ioc_type="IPv4",
            providers=["OTX", "ThreatFox", "AbuseIPDB"],
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            threat_actors=["Cobalt Strike"],
            malware_families=["AsyncRat"],
            campaigns=[],
            mitre_attack=["T1059"],
            tags=["c2"],
            references=["https://example.com"],
            community_reports=5
        )
        
        assessment = analyzer.analyze(malicious_intel)
        self.assertGreaterEqual(assessment.ioc_intelligence_score, 70)
        self.assertIn(assessment.classification, ["LIKELY MALICIOUS", "HIGH CONFIDENCE MALICIOUS"])

    def test_aggregator_case_normalization(self):
        aggregator = IntelAggregator()
        intel1 = Intel(source="OTX", queried_ioc="1.1.1.1", queried_ioc_type="IPv4", threat_actors=["COBALT STRIKE"])
        intel2 = Intel(source="ThreatFox", queried_ioc="1.1.1.1", queried_ioc_type="IPv4", threat_actors=["Cobalt Strike"])
        
        consolidated = aggregator.aggregate([intel1, intel2])
        # Title case should be preferred over ALL CAPS
        self.assertEqual(consolidated.threat_actors, ["Cobalt Strike"])

    def test_client_missing_key_graceful_fallback(self):
        # Clients should return empty dict when keys are missing/placeholder without throwing uncaught errors
        client_abuse = AbuseIPDBClient()
        client_otx = OTXClient()
        client_fox = ThreatFoxClient()
        
        ioc = IOC(ioc_type="IPv4", ioc_value="127.0.0.1")
        
        res_abuse = client_abuse.lookup(ioc)
        res_otx = client_otx.lookup(ioc)
        res_fox = client_fox.lookup(ioc)
        
        self.assertEqual(res_abuse, {})
        self.assertEqual(res_otx, {})
        self.assertEqual(res_fox, {})


if __name__ == "__main__":
    unittest.main()
