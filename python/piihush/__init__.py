"""High-speed PII and secret masking for RAG and LLM pipelines."""

from collections.abc import Iterable
from functools import lru_cache

from ._core import ENTITIES, Masker, Match, __version__

__all__ = ["ENTITIES", "Masker", "Match", "__version__", "detect", "mask", "mask_batch"]


@lru_cache(maxsize=1)
def _default_masker() -> Masker:
    return Masker()


def mask(text: str) -> str:
    """Mask every built-in entity in ``text``."""
    return _default_masker().mask(text)


def mask_batch(texts: Iterable[str]) -> list[str]:
    """Mask every built-in entity in each of ``texts``."""
    return _default_masker().mask_batch(texts)


def detect(text: str) -> list[Match]:
    """Return the built-in entities found in ``text``."""
    return _default_masker().detect(text)
