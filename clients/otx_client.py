import logging
from typing import Any

import requests

from config.config_loader import get_api_key
from models.ioc import IOC

logger = logging.getLogger("ioc_insight")


class OTXClient:
    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self):
        self.api_key = get_api_key("otx")
        self.headers = {
            "X-OTX-API-KEY": self.api_key or ""
        }

    def lookup(
        self,
        ioc: IOC,
        section: str = "general"
    ) -> dict[str, Any]:
        if not self.api_key:
            raise RuntimeError("OTX API key not configured.")

        otx_type_map = {
            "IPv4": "IPv4",
            "IPv6": "IPv6",
            "domain": "domain",
            "hostname": "hostname",
            "file": "file",
            "hash": "file",
            "url": "url"
        }
        otx_type = otx_type_map.get(ioc.ioc_type, ioc.ioc_type)

        url = (
            f"{self.BASE_URL}/"
            f"{otx_type}/"
            f"{ioc.ioc_value}/"
            f"{section}"
        )

        try:
            response = requests.get(
                url=url,
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(
                f"OTX lookup failed for {ioc.ioc_value}: {e}"
            ) from e
