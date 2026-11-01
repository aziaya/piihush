"""Optional model-based detection of names and places.

Install with ``pip install piihush[ner]``. The model is downloaded on first use.
"""

import re
from collections.abc import Callable, Iterable

from ._core import Masker, Match

Span = tuple[str, int, int]
Recognizer = Callable[[str], Iterable[Span]]

MODEL_REPO = "dslim/bert-base-NER"
MODEL_REVISION = "d1a3e8f13f8c3566299d95fcfc9a8d2382a9affc"
_MODEL_LABELS = {"PER": "PERSON", "LOC": "ADDRESS"}
_MAX_TOKENS = 512
_STRIDE = 64
_DEFAULT_TEMPLATE = "[{entity}_REDACTED]"


def _decode(tokens: list[tuple[str | None, int, int]], text: str) -> list[Span]:
    """Join tagged tokens into spans covering whole words.

    The model may tag only part of a word, and masking just that part would
    leave the rest of the name in the output.
    """
    spans: list[Span] = []
    for entity, start, end in tokens:
        if entity is None or start == end:
            continue
        while start > 0 and text[start - 1].isalnum():
            start -= 1
        while end < len(text) and text[end].isalnum():
            end += 1
        if spans and spans[-1][0] == entity and start - spans[-1][2] <= 1:
            spans[-1] = (entity, spans[-1][1], max(end, spans[-1][2]))
        else:
            spans.append((entity, start, end))
    return spans


def _other_occurrences(found: list[Span], text: str, allow: set[str]) -> list[Span]:
    """Find repeats of each hit, since the model can tag a name once and miss it later."""
    terms: dict[str, str] = {}
    for entity, start, end in found:
        for term in text[start:end].split():
            if len(term) >= 3 and term.lower() not in allow:
                terms.setdefault(term, entity)
    if not terms:
        return []
    alternatives = "|".join(re.escape(t) for t in sorted(terms, key=len, reverse=True))
    return [
        (terms[m.group()], m.start(), m.end())
        for m in re.finditer(rf"(?<!\w)(?:{alternatives})(?!\w)", text)
    ]


class OnnxRecognizer:
    """Finds people and places with a pinned ONNX token classification model."""

    def __init__(self, repo: str = MODEL_REPO, revision: str = MODEL_REVISION) -> None:
        try:
            import json

            import numpy
            import onnxruntime
            from huggingface_hub import hf_hub_download
            from tokenizers import Tokenizer
        except ImportError as error:
            raise ImportError(
                "model-based detection needs extra packages: pip install piihush[ner]"
            ) from error

        def fetch(name: str) -> str:
            return hf_hub_download(repo, f"onnx/{name}", revision=revision)

        self._numpy = numpy
        self._session = onnxruntime.InferenceSession(
            fetch("model.onnx"), providers=["CPUExecutionProvider"]
        )
        self._inputs = {i.name for i in self._session.get_inputs()}
        self._tokenizer = Tokenizer.from_file(fetch("tokenizer.json"))
        self._tokenizer.enable_truncation(max_length=_MAX_TOKENS, stride=_STRIDE)
        with open(fetch("config.json"), encoding="utf-8") as config:
            id2label = json.load(config)["id2label"]
        self._labels = {int(i): label for i, label in id2label.items()}

    def __call__(self, text: str) -> list[Span]:
        numpy = self._numpy
        first = self._tokenizer.encode(text)
        spans: list[Span] = []
        for window in [first, *first.overflowing]:
            ids = numpy.array([window.ids], dtype=numpy.int64)
            feed = {
                "input_ids": ids,
                "attention_mask": numpy.array([window.attention_mask], dtype=numpy.int64),
                "token_type_ids": numpy.zeros_like(ids),
            }
            logits = self._session.run(
                None, {k: v for k, v in feed.items() if k in self._inputs}
            )[0][0]
            tokens = [
                (_MODEL_LABELS.get(self._labels[token].partition("-")[2]), start, end)
                for token, (start, end) in zip(logits.argmax(axis=-1).tolist(), window.offsets)
            ]
            # Windows overlap, so each is decoded alone and `detect` merges them.
            spans += _decode(tokens, text)
        return spans


class NerMasker:
    """A ``Masker`` that also masks what a recognizer finds.

    Takes the same arguments as ``Masker``. ``recognizer`` is any callable that
    returns ``(entity, start, end)`` tuples and defaults to ``OnnxRecognizer``.
    This is far slower than ``Masker``, and sends nothing over the network apart
    from the first model download.
    """

    def __init__(
        self,
        entities: list[str] | None = None,
        *,
        custom_patterns: dict[str, str] | None = None,
        deny_list: dict[str, list[str]] | None = None,
        allow_list: list[str] | None = None,
        template: str | None = None,
        recognizer: Recognizer | None = None,
    ) -> None:
        self._masker = Masker(
            entities,
            custom_patterns=custom_patterns,
            deny_list=deny_list,
            allow_list=allow_list,
            template=template,
        )
        self._recognizer = recognizer if recognizer is not None else OnnxRecognizer()
        self._enabled = None if entities is None else set(entities)
        self._allow = {value.lower() for value in allow_list or ()}
        self._template = template if template is not None else _DEFAULT_TEMPLATE

    def detect(self, text: str) -> list[Match]:
        """Return disjoint entities in order, as ``Masker.detect`` does."""
        spans = [(m.entity, m.start, m.end) for m in self._masker.detect(text)]
        found = [
            (entity, start, end)
            for entity, start, end in self._recognizer(text)
            if (self._enabled is None or entity in self._enabled)
            and text[start:end].lower() not in self._allow
        ]
        spans += found + _other_occurrences(found, text, self._allow)

        # Overlaps become their union, labelled by the longest member, so no
        # fragment of either survives.
        spans.sort(key=lambda span: (span[1], -span[2]))
        merged: list[list] = []
        for entity, start, end in spans:
            if merged and start < merged[-1][2]:
                last = merged[-1]
                last[2] = max(last[2], end)
                if end - start > last[3]:
                    last[0], last[3] = entity, end - start
            else:
                merged.append([entity, start, end, end - start])
        return [Match(e, s, n, text[s:n]) for e, s, n, _ in merged]

    def mask(self, text: str) -> str:
        """Return ``text`` with every detected entity replaced."""
        parts = []
        cursor = 0
        for match in self.detect(text):
            parts += [text[cursor : match.start], self._template.replace("{entity}", match.entity)]
            cursor = match.end
        parts.append(text[cursor:])
        return "".join(parts)

    def mask_batch(self, texts: Iterable[str]) -> list[str]:
        """Mask each of ``texts``, one at a time."""
        return [self.mask(text) for text in texts]
