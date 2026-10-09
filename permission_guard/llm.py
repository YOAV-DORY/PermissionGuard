"""Adapter that lets ``run_agent`` talk to Claude through the official Anthropic SDK.

The SDK is an optional dependency (``pip install -r requirements-llm.txt``); the rest
of the package works without it.
"""

from __future__ import annotations

from typing import Any

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Models for which the API-side refusal fallback ("default" mode) is available.
FALLBACK_MODELS = frozenset({"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"})


class LLMUnavailable(RuntimeError):
    """The Anthropic SDK is missing or no credentials are configured."""


class AnthropicLLM:
    """Calls ``messages.create`` once per turn. Streaming is unnecessary at this size."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        client: Any = None,
        max_tokens: int = 16_000,
        effort: str | None = None,
    ) -> None:
        if client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover - exercised only without the extra installed
                raise LLMUnavailable("the anthropic package is not installed: pip install -r requirements-llm.txt") from exc
            client = anthropic.Anthropic()  # credentials: ANTHROPIC_API_KEY or an `ant auth login` profile
        self.client = client
        self.model = model
        self.max_tokens = max_tokens
        self.effort = effort

    def create(self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Any:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": messages,
            "tools": tools,
        }
        if self.effort:
            kwargs["output_config"] = {"effort": self.effort}
        if self.model in FALLBACK_MODELS:
            # If a safety classifier declines, the API re-runs the request on a fallback model.
            kwargs["betas"] = [FALLBACK_BETA]
            kwargs["extra_body"] = {"fallbacks": "default"}
            return self.client.beta.messages.create(**kwargs)
        return self.client.messages.create(**kwargs)
