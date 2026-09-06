import os
import yaml

_config = None

def _load_config():
    global _config
    if _config is not None:
        return _config

    config_path = "config/config.yaml"
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as file:
                _config = yaml.safe_load(file) or {}
        except Exception:
            _config = {}
    else:
        _config = {}
    return _config

def get_source_config(source_name: str) -> dict:
    config = _load_config()
    return config.get("sources", {}).get(source_name, {})

def get_api_key(source_name: str) -> str | None:
    env_var_map = {
        "otx": "OTX_API_KEY",
        "abuseipdb": "ABUSEIPDB_API_KEY",
        "threatfox": "THREATFOX_API_KEY"
    }
    env_var_name = env_var_map.get(source_name.lower())
    if env_var_name and os.getenv(env_var_name):
        return os.getenv(env_var_name)

    source_config = get_source_config(source_name)
    api_key = source_config.get("api_key")
    if api_key and not api_key.startswith("YOUR_"):
        return api_key
    return None