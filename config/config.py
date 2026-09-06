import os

DEVELOPMENT_MODE = os.getenv("IOC_INSIGHT_DEV_MODE", "false").lower() in ("true", "1", "yes")