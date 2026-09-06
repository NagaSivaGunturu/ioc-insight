import logging
import requests

from config.config_loader import get_api_key
from models.ioc import IOC

logger = logging.getLogger("ioc_insight")


class ThreatFoxClient:

    BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self):
        self.api_key = get_api_key("threatfox")

    def lookup(self, ioc: IOC):
        if not self.api_key:
            raise RuntimeError("ThreatFox API key not configured.")

        headers = {
            "Auth-Key": self.api_key,
            "Accept": "application/json"
        }

        payload = {
            "query": "search_ioc",
            "search_term": ioc.ioc_value
        }


        try:
            response = requests.post(
                self.BASE_URL,
                headers=headers,
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(
                f"ThreatFox lookup failed for {ioc.ioc_value}: {e}"
            )
