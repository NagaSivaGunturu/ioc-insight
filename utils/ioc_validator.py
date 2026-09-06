import ipaddress
import re
from typing import Tuple


class IOCValidator:

    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
    SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
    SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
    URL_REGEX = re.compile(r"^https?://", re.IGNORECASE)

    @classmethod
    def detect_type(cls, ioc_value: str) -> str:
        ioc_value = ioc_value.strip()

        # IPv4 Check
        try:
            ip = ipaddress.ip_address(ioc_value)
            if ip.version == 4:
                return "IPv4"
            elif ip.version == 6:
                return "IPv6"
        except ValueError:
            pass

        # URL Check
        if cls.URL_REGEX.match(ioc_value):
            return "url"

        # Hashes
        if cls.MD5_REGEX.match(ioc_value) or cls.SHA1_REGEX.match(ioc_value) or cls.SHA256_REGEX.match(ioc_value):
            return "hash"

        # Domain
        if cls.DOMAIN_REGEX.match(ioc_value):
            return "domain"

        return "unknown"

    @classmethod
    def validate_and_normalize(cls, ioc_value: str, ioc_type: str | None = None) -> Tuple[str, str]:
        ioc_value = ioc_value.strip()
        detected_type = cls.detect_type(ioc_value)

        if not ioc_type or ioc_type.lower() == "auto":
            final_type = detected_type
        else:
            final_type = ioc_type.strip()

        return ioc_value, final_type
