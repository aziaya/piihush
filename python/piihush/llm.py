"""Use any LLM without sending it your PII.

``PrivacyGuard`` swaps values for numbered tokens such as ``[EMAIL_1]`` and puts them
back in the reply. ``PrivateChat`` does that around a chat with any provider that has
an OpenAI-compatible API. Everything here uses only the standard library.
"""

import json
import os
import re
import threading
import urllib.error
import urllib.request
from collections.abc import Iterable, Iterator
from typing import Any

from ._core import Masker

_TOKEN = re.compile(r"\[[A-Z][A-Z0-9_]*_[0-9]+\]")
_PARTIAL_TOKEN = re.compile(r"\[[A-Z0-9_]*\Z")
_MAX_TOKEN_LENGTH = 64

# Provider name to (base URL, environment variable holding the API key).
PROVIDERS = {
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "anthropic": ("https://api.anthropic.com/v1", "ANTHROPIC_API_KEY"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY"),
    "deepseek": ("https://api.deepseek.com", "DEEPSEEK_API_KEY"),
    "grok": ("https://api.x.ai/v1", "XAI_API_KEY"),
    "ollama": ("http://localhost:11434/v1", None),
    "llamacpp": ("http://localhost:8080/v1", None),
}


class LLMError(RuntimeError):
    """A provider rejected a request or could not be reached."""


class PrivacyGuard:
    """Reversibly masks text. Thread-safe.

    Use one guard per conversation. A guard remembers every value it has masked, so
    sharing one between users could reveal one user's values to another.
    """

    def __init__(self, masker: Any = None) -> None:
        self._masker = masker if masker is not None else Masker()
        self._lock = threading.Lock()
        self._values: dict[str, str] = {}
        self._tokens: dict[tuple[str, str], str] = {}
        self._counts: dict[str, int] = {}

    def _token_for(self, entity: str, value: str, text: str) -> str:
        key = (entity, value)
        if key not in self._tokens:
            count = self._counts.get(entity, 0) + 1
            # Skip tokens the text already contains, so restoring can't replace them.
            while f"[{entity}_{count}]" in text:
                count += 1
            self._counts[entity] = count
            token = f"[{entity}_{count}]"
            self._tokens[key] = token
            self._values[token] = value
        return self._tokens[key]

    def mask(self, text: str) -> str:
        """Replace each value with a token. The same value always gets the same token."""
        matches = self._masker.detect(text)
        parts = []
        cursor = 0
        with self._lock:
            for match in matches:
                parts.append(text[cursor : match.start])
                parts.append(self._token_for(match.entity, match.text, text))
                cursor = match.end
        parts.append(text[cursor:])
        return "".join(parts)

    def restore(self, text: str) -> str:
        """Put the original values back. Tokens this guard didn't create are left alone."""
        with self._lock:
            return _TOKEN.sub(lambda m: self._values.get(m.group(), m.group()), text)

    def restore_stream(self, chunks: Iterable[str]) -> Iterator[str]:
        """Restore a streamed reply, holding back any token split across chunks."""
        pending = ""
        for chunk in chunks:
            pending += chunk
            partial = _PARTIAL_TOKEN.search(pending, max(0, len(pending) - _MAX_TOKEN_LENGTH))
            safe_end = partial.start() if partial else len(pending)
            if safe_end:
                yield self.restore(pending[:safe_end])
                pending = pending[safe_end:]
        if pending:
            yield self.restore(pending)

    def reset(self) -> None:
        """Forget every value."""
        with self._lock:
            self._values.clear()
            self._tokens.clear()
            self._counts.clear()


class PrivateChat:
    """A chat with any OpenAI-compatible provider that never sends it detected PII.

    Pass a name from ``PROVIDERS``, or ``base_url`` for any other provider. The
    conversation is stored masked, and replies are restored for you.
    """

    def __init__(
        self,
        provider: str | None = None,
        model: str = "",
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        guard: PrivacyGuard | None = None,
        system: str | None = None,
        timeout: float = 120,
    ) -> None:
        if not model:
            raise ValueError("model is required")
        if provider is not None and provider not in PROVIDERS:
            raise ValueError(f"unknown provider {provider!r}: expected one of {list(PROVIDERS)}")
        if provider is None and base_url is None:
            raise ValueError("pass a provider name or a base_url")

        default_url, key_variable = PROVIDERS.get(provider, (None, None))
        self._url = (base_url or default_url).rstrip("/") + "/chat/completions"
        self._key = api_key or (os.environ.get(key_variable) if key_variable else None)
        if key_variable and base_url is None and not self._key:
            raise ValueError(f"set {key_variable} or pass api_key")
        self._model = model
        self._timeout = timeout
        self.guard = guard if guard is not None else PrivacyGuard()
        self._messages: list[dict[str, str]] = []
        if system:
            self._messages.append({"role": "system", "content": self.guard.mask(system)})

    @property
    def messages(self) -> list[dict[str, str]]:
        """The conversation exactly as the provider sees it, with tokens in place."""
        return [dict(message) for message in self._messages]

    def _open(self, options: dict, stream: bool):
        body = {"model": self._model, "messages": self._messages, "stream": stream, **options}
        headers = {"Content-Type": "application/json"}
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        request = urllib.request.Request(
            self._url, data=json.dumps(body).encode(), headers=headers, method="POST"
        )
        try:
            return urllib.request.urlopen(request, timeout=self._timeout)
        except urllib.error.HTTPError as error:
            detail = error.read(500).decode("utf-8", "replace")
            raise LLMError(f"provider returned {error.code}: {detail}") from error
        except OSError as error:
            raise LLMError(f"could not reach {self._url}: {error}") from error

    def send(self, prompt: str, **options: Any) -> str:
        """Send ``prompt`` and return the restored reply.

        ``options`` are passed to the provider, such as ``temperature``.
        """
        self._messages.append({"role": "user", "content": self.guard.mask(prompt)})
        try:
            with self._open(options, stream=False) as response:
                reply = json.load(response)["choices"][0]["message"]["content"] or ""
        except (LLMError, KeyError, IndexError, ValueError) as error:
            self._messages.pop()
            if isinstance(error, LLMError):
                raise
            raise LLMError(f"unexpected reply from provider: {error!r}") from error
        self._messages.append({"role": "assistant", "content": reply})
        return self.guard.restore(reply)

    def _deltas(self, response) -> Iterator[str]:
        for line in response:
            if not line.startswith(b"data:"):
                continue
            data = line[5:].strip()
            if data == b"[DONE]":
                return
            choices = json.loads(data).get("choices") or [{}]
            content = (choices[0].get("delta") or {}).get("content")
            if content:
                yield content

    def stream(self, prompt: str, **options: Any) -> Iterator[str]:
        """Like ``send``, but yield the restored reply as it arrives."""
        self._messages.append({"role": "user", "content": self.guard.mask(prompt)})
        try:
            response = self._open(options, stream=True)
        except LLMError:
            self._messages.pop()
            raise
        collected: list[str] = []

        def tee(deltas: Iterable[str]) -> Iterator[str]:
            for delta in deltas:
                collected.append(delta)
                yield delta

        with response:
            yield from self.guard.restore_stream(tee(self._deltas(response)))
        self._messages.append({"role": "assistant", "content": "".join(collected)})

    def reset(self) -> None:
        """Clear the conversation and forget every masked value."""
        self._messages.clear()
        self.guard.reset()
