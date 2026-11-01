from collections.abc import Iterable, Mapping, Sequence
from typing import Final, final

ENTITIES: Final[list[str]]
__version__: Final[str]

@final
class Match:
    entity: str
    start: int
    end: int
    text: str
    def __new__(cls, entity: str, start: int, end: int, text: str) -> Match: ...

@final
class Masker:
    def __new__(
        cls,
        entities: Sequence[str] | None = None,
        *,
        custom_patterns: Mapping[str, str] | None = None,
        deny_list: Mapping[str, Sequence[str]] | None = None,
        allow_list: Sequence[str] | None = None,
        template: str | None = None,
    ) -> Masker: ...
    def mask(self, text: str) -> str: ...
    def mask_batch(self, texts: Iterable[str]) -> list[str]: ...
    def detect(self, text: str) -> list[Match]: ...
