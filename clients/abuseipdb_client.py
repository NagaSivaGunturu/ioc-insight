import logging
import requests

from config.config_loader import get_api_key
from models.ioc import IOC

logger = logging.getLogger("ioc_insight")


class AbuseIPDBClient:
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self):
        self.api_key = get_api_key("abuseipdb")

    def lookup(self, ioc: IOC):
        if not self.api_key:
            raise RuntimeError("AbuseIPDB API key not configured.")

        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        params = {
            "ipAddress": ioc.ioc_value,
            "maxAgeInDays": 365,
            "verbose": ""
        }
        try:
            response = requests.get(
                self.BASE_URL,
                headers=headers,
                params=params,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(
                f"AbuseIPDB lookup failed for {ioc.ioc_value}: {e}"
            )
