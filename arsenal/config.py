"""Configuration handling for PENTRIX ARSENAL.

Config lives at ~/.arsenal/config.json. The LLM API key is NEVER stored
in the config file; it is read from the ARSENAL_LLM_API_KEY environment
variable only (see get_llm_key()).
"""

import copy
import json
import os

CONFIG_PATH = os.path.expanduser("~/.arsenal/config.json")

DEFAULTS = {
    "profile": "default",
    "profiles": {
        "default": {
            "threads": 20,
            "timeout": 10,
            "user_agent": "pentrix-arsenal/0.1.0",
        },
        "aggressive": {
            "threads": 50,
            "timeout": 6,
        },
    },
    "safe_mode": True,
    "stealth": {
        "enabled": False,
        "min_delay": 0.5,
        "max_delay": 2.0,
        "rotate_ua": True,
    },
    "llm": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
    },
}


def _merge(base, override):
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def load():
    """Load config from disk merged over defaults (defaults win on missing)."""
    cfg = copy.deepcopy(DEFAULTS)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            _merge(cfg, data)
    except (OSError, ValueError):
        pass
    return cfg


def save(cfg):
    """Persist config to disk. Never stores the LLM API key."""
    cfg = dict(cfg)
    cfg.pop("llm_api_key", None)
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    os.replace(tmp, CONFIG_PATH)


def get_profile(cfg):
    """Return the active profile dict, falling back to 'default'."""
    profiles = cfg.get("profiles") or {}
    name = cfg.get("profile") or "default"
    profile = profiles.get(name) or profiles.get("default") or {}
    return dict(profile)


def get_llm_key():
    """Return the LLM API key from the environment, or None.

    This is the ONLY supported source for the key; it is never read
    from or written to the config file.
    """
    return os.environ.get("ARSENAL_LLM_API_KEY")
