"""Pluggable multi-provider LLM client for PENTRIX ARSENAL.

Standard library only (urllib). Providers:

* openai     - OpenAI-compatible /chat/completions API (default).
               Key: ARSENAL_LLM_API_KEY (also honors OPENAI_API_KEY).
* anthropic  - Anthropic Messages API. Key: ANTHROPIC_API_KEY (also
               honors ARSENAL_LLM_API_KEY when provider=anthropic).
* custom     - any OpenAI-compatible endpoint; same wire format as openai.

Selection (first match wins):
    ARSENAL_LLM_PROVIDER env var (openai|anthropic|custom), else
    "anthropic" when only ANTHROPIC_API_KEY is set, else "openai".

Config knobs (env, then ctx.config["llm"] overrides for non-secrets):
    ARSENAL_LLM_BASE_URL / ARSENAL_LLM_MODEL
    llm.max_calls   - cost guard: max LLM calls per triage_all run
    llm.max_tokens  - default max_tokens per call

The API key can only ever come from the environment; config may override
base_url and model but never the key. Library functions never print and
never log key material.
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
ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1"
ANTHROPIC_MODEL = "claude-haiku-4-5"
ANTHROPIC_VERSION = "2023-06-01"


def _provider() -> str:
    explicit = os.environ.get("ARSENAL_LLM_PROVIDER", "").strip().lower()
    if explicit in ("openai", "anthropic", "custom"):
        return explicit
    if (not os.environ.get("ARSENAL_LLM_API_KEY", "").strip()
            and os.environ.get("ANTHROPIC_API_KEY", "").strip()):
        return "anthropic"
    return "openai"


def _api_key(provider: str) -> str:
    if provider == "anthropic":
        return (os.environ.get("ANTHROPIC_API_KEY", "").strip()
                or os.environ.get("ARSENAL_LLM_API_KEY", "").strip())
    return (os.environ.get("ARSENAL_LLM_API_KEY", "").strip()
            or os.environ.get("OPENAI_API_KEY", "").strip())


def llm_available() -> bool:
    """True when an API key for the selected provider is present."""
    return bool(_api_key(_provider()))


def provider_info() -> dict:
    """Non-secret provider summary for diagnostics (never includes the key)."""
    provider = _provider()
    base_url, model = _resolve_config(provider=provider)
    return {
        "provider": provider,
        "base_url": base_url,
        "model": model,
        "key_present": llm_available(),
        "key_source": ("ANTHROPIC_API_KEY" if provider == "anthropic"
                       and os.environ.get("ANTHROPIC_API_KEY", "").strip()
                       else "ARSENAL_LLM_API_KEY"),
    }


def _llm_cfg(ctx):
    if ctx is None:
        return {}
    cfg = getattr(ctx, "config", None)
    llm_cfg = None
    if isinstance(cfg, dict):
        llm_cfg = cfg.get("llm")
    elif cfg is not None and hasattr(cfg, "get"):
        try:
            llm_cfg = cfg.get("llm")
        except Exception:
            llm_cfg = None
    return llm_cfg if isinstance(llm_cfg, dict) else {}


def _resolve_config(ctx=None, provider=None):
    """Resolve (base_url, model) for a provider: env first, then ctx config."""
    provider = provider or _provider()
    if provider == "anthropic":
        base_url = os.environ.get("ARSENAL_LLM_BASE_URL", ANTHROPIC_BASE_URL).rstrip("/")
        model = os.environ.get("ARSENAL_LLM_MODEL", ANTHROPIC_MODEL)
    else:
        base_url = os.environ.get("ARSENAL_LLM_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
        model = os.environ.get("ARSENAL_LLM_MODEL", DEFAULT_MODEL)
    llm_cfg = _llm_cfg(ctx)
    if llm_cfg.get("base_url"):
        base_url = str(llm_cfg["base_url"]).rstrip("/")
    if llm_cfg.get("model"):
        model = str(llm_cfg["model"])
    return base_url, model


def cost_guard(ctx=None) -> dict:
    """Cost-guard settings: {"max_calls": int, "max_tokens": int}."""
    llm_cfg = _llm_cfg(ctx)
    try:
        max_calls = int(os.environ.get("ARSENAL_LLM_MAX_CALLS",
                                       llm_cfg.get("max_calls", 20)))
    except (TypeError, ValueError):
        max_calls = 20
    try:
        max_tokens = int(os.environ.get("ARSENAL_LLM_MAX_TOKENS",
                                        llm_cfg.get("max_tokens", 1200)))
    except (TypeError, ValueError):
        max_tokens = 1200
    return {"max_calls": max(1, max_calls), "max_tokens": max(1, max_tokens)}


def _post(url, payload: dict, headers: dict, timeout: int) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
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
        return json.loads(body)
    except ValueError as e:
        raise LLMError("LLM returned non-JSON response: %s" % e)


def _chat_openai(messages: list, max_tokens: int, timeout: int, ctx=None) -> str:
    provider = _provider()
    api_key = _api_key(provider)
    if not api_key:
        raise LLMError("no API key set (ARSENAL_LLM_API_KEY or OPENAI_API_KEY)")
    base_url, model = _resolve_config(ctx, provider=provider)
    data = _post(
        base_url + "/chat/completions",
        {"model": model, "messages": messages, "max_tokens": max_tokens,
         "temperature": 0.2},
        {"Content-Type": "application/json",
         "Authorization": "Bearer " + api_key},
        timeout,
    )
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise LLMError("Unexpected LLM response format: %s" % e)
    return content if isinstance(content, str) else str(content)


def _chat_anthropic(messages: list, max_tokens: int, timeout: int, ctx=None) -> str:
    api_key = _api_key("anthropic")
    if not api_key:
        raise LLMError("no API key set (ANTHROPIC_API_KEY or ARSENAL_LLM_API_KEY)")
    base_url, model = _resolve_config(ctx, provider="anthropic")
    system = ""
    convo = []
    for m in messages or []:
        role = str(m.get("role", "user"))
        content = str(m.get("content", ""))
        if role == "system":
            system += content + "\n"
        else:
            convo.append({"role": "user" if role != "assistant" else "assistant",
                          "content": content})
    payload = {"model": model, "max_tokens": max_tokens,
               "messages": convo or [{"role": "user", "content": ""}]}
    if system.strip():
        payload["system"] = system.strip()
    data = _post(
        base_url + "/messages",
        payload,
        {"Content-Type": "application/json",
         "x-api-key": api_key,
         "anthropic-version": ANTHROPIC_VERSION},
        timeout,
    )
    try:
        blocks = data["content"]
        text = "".join(b.get("text", "") for b in blocks
                       if isinstance(b, dict) and b.get("type") == "text")
    except (KeyError, TypeError) as e:
        raise LLMError("Unexpected Anthropic response format: %s" % e)
    if not text:
        raise LLMError("Anthropic returned no text content")
    return text


def chat(messages: list, max_tokens: int = 800, timeout: int = 30, ctx=None) -> str:
    """Send messages to the configured provider; return assistant text.

    Raises LLMError on any failure. Callers are expected to catch it.
    """
    provider = _provider()
    if provider == "anthropic":
        return _chat_anthropic(messages, max_tokens, timeout, ctx)
    return _chat_openai(messages, max_tokens, timeout, ctx)
