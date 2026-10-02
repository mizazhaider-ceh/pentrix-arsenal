"""Pluggable OpenAI-compatible LLM provider for PENTRIX ARSENAL.

Standard library only (urllib). Never reads or stores the API key beyond the
single request that needs it. Library functions never print.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


class LLMError(Exception):
    """Raised when an LLM request cannot be completed."""


DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"


def llm_available() -> bool:
    """True when an API key is present in the environment."""
    return bool(os.environ.get("ARSENAL_LLM_API_KEY", "").strip())


def _resolve_config(ctx=None):
    """Resolve base_url and model: env vars first, then ctx.config['llm'] overrides.

    The API key can only ever come from the environment; config may override
    base_url and model but never the key.
    """
    base_url = os.environ.get("ARSENAL_LLM_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    model = os.environ.get("ARSENAL_LLM_MODEL", DEFAULT_MODEL)
    if ctx is not None:
        cfg = getattr(ctx, "config", None)
        llm_cfg = None
        if isinstance(cfg, dict):
            llm_cfg = cfg.get("llm")
        elif cfg is not None and hasattr(cfg, "get"):
            try:
                llm_cfg = cfg.get("llm")
            except Exception:
                llm_cfg = None
        if isinstance(llm_cfg, dict):
            if llm_cfg.get("base_url"):
                base_url = str(llm_cfg["base_url"]).rstrip("/")
            if llm_cfg.get("model"):
                model = str(llm_cfg["model"])
    return base_url, model


def chat(messages: list, max_tokens: int = 800, timeout: int = 30, ctx=None) -> str:
    """POST to {base_url}/chat/completions and return the assistant content.

    Raises LLMError on any failure. Callers are expected to catch it.
    """
    api_key = os.environ.get("ARSENAL_LLM_API_KEY", "").strip()
    if not api_key:
        raise LLMError("ARSENAL_LLM_API_KEY is not set")
    base_url, model = _resolve_config(ctx)
    url = base_url + "/chat/completions"
    payload = json.dumps(
        {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_key,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            detail = ""
        raise LLMError("LLM request failed: HTTP %s %s" % (e.code, detail))
    except urllib.error.URLError as e:
        raise LLMError("LLM request failed: %s" % e)
    except TimeoutError:
        raise LLMError("LLM request timed out after %ss" % timeout)
    except Exception as e:  # connection reset, SSL errors, etc.
        raise LLMError("LLM request failed: %s" % e)

    try:
        data = json.loads(body)
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError) as e:
        raise LLMError("Unexpected LLM response format: %s" % e)
    return content if isinstance(content, str) else str(content)
