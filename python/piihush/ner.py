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


def _erf(x):
    """Vectorized error function (Abramowitz and Stegun 7.1.26), accurate to 1.5e-7."""
    import numpy

    t = 1.0 / (1.0 + 0.3275911 * numpy.abs(x))
    poly = t * (
        0.254829592
        + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429)))
    )
    return numpy.sign(x) * (1.0 - poly * numpy.exp(-x * x))


def _load_safetensors(path: str):
    """Read a safetensors file as named float32 arrays."""
    import json

    import numpy

    with open(path, "rb") as file:
        header_size = int.from_bytes(file.read(8), "little")
        header = json.loads(file.read(header_size))
        data = file.read()
    # Copied because tensors in the file aren't aligned, and NumPy skips its fast
    # matrix routines for unaligned arrays.
    return {
        name: numpy.frombuffer(
            data[info["data_offsets"][0] : info["data_offsets"][1]], dtype="<f4"
        )
        .reshape(info["shape"])
        .astype(numpy.float32)
        for name, info in header.items()
        if name != "__metadata__"
    }


class _Bert:
    """BERT token classification, computed with NumPy.

    Written out by hand so the add-on needs no compiled inference runtime, which
    is what lets it install on every platform and Python version piihush supports.
    Inputs are single unpadded sequences, so no attention mask is needed.
    """

    def __init__(self, weights: dict, config: dict) -> None:
        self._w = weights
        self._heads = config["num_attention_heads"]
        self._layers = config["num_hidden_layers"]

    def _dense(self, prefix: str, x):
        return x @ self._w[f"{prefix}.weight"].T + self._w[f"{prefix}.bias"]

    def _norm(self, prefix: str, x):
        import numpy

        mean = x.mean(axis=-1, keepdims=True)
        variance = ((x - mean) ** 2).mean(axis=-1, keepdims=True)
        scaled = (x - mean) / numpy.sqrt(variance + 1e-12)
        return scaled * self._w[f"{prefix}.weight"] + self._w[f"{prefix}.bias"]

    def _attention(self, prefix: str, x):
        import numpy

        length, width = x.shape
        size = width // self._heads

        def split(name: str):
            projected = self._dense(f"{prefix}.{name}", x)
            return projected.reshape(length, self._heads, size).transpose(1, 0, 2)

        query, key, value = split("query"), split("key"), split("value")
        scores = query @ key.transpose(0, 2, 1) / numpy.sqrt(numpy.float32(size))
        scores = scores - scores.max(axis=-1, keepdims=True)
        probabilities = numpy.exp(scores)
        probabilities /= probabilities.sum(axis=-1, keepdims=True)
        return (probabilities @ value).transpose(1, 0, 2).reshape(length, width)

    def logits(self, ids: list[int]):
        import numpy

        w = self._w
        ids_array = numpy.asarray(ids)
        x = (
            w["bert.embeddings.word_embeddings.weight"][ids_array]
            + w["bert.embeddings.position_embeddings.weight"][: len(ids)]
            + w["bert.embeddings.token_type_embeddings.weight"][0]
        )
        x = self._norm("bert.embeddings.LayerNorm", x)
        for index in range(self._layers):
            layer = f"bert.encoder.layer.{index}"
            attended = self._attention(f"{layer}.attention.self", x)
            attended = self._dense(f"{layer}.attention.output.dense", attended)
            x = self._norm(f"{layer}.attention.output.LayerNorm", x + attended)
            hidden = self._dense(f"{layer}.intermediate.dense", x)
            hidden = 0.5 * hidden * (1.0 + _erf(hidden * 0.70710678))  # exact GELU
            hidden = self._dense(f"{layer}.output.dense", hidden)
            x = self._norm(f"{layer}.output.LayerNorm", x + hidden)
        return self._dense("classifier", x)


class BertRecognizer:
    """Finds people and places with a pinned BERT token classification model."""

    def __init__(self, repo: str = MODEL_REPO, revision: str = MODEL_REVISION) -> None:
        try:
            import json

            import numpy  # noqa: F401
            from huggingface_hub import hf_hub_download
            from tokenizers import Tokenizer
        except ImportError as error:
            raise ImportError(
                "model-based detection needs extra packages: pip install 'piihush[ner]'"
            ) from error

        def fetch(name: str) -> str:
            return hf_hub_download(repo, name, revision=revision)

        with open(fetch("config.json"), encoding="utf-8") as config_file:
            config = json.load(config_file)
        self._labels = {int(i): label for i, label in config["id2label"].items()}
        self._logits = self._onnx_logits(fetch) or _Bert(
            _load_safetensors(fetch("model.safetensors")), config
        ).logits
        self._tokenizer = Tokenizer.from_file(fetch("onnx/tokenizer.json"))
        self._tokenizer.enable_truncation(max_length=_MAX_TOKENS, stride=_STRIDE)

    @staticmethod
    def _onnx_logits(fetch: Callable[[str], str]) -> Callable | None:
        """Use onnxruntime when it's installed: same output, about twice as fast."""
        try:
            import numpy
            import onnxruntime
        except ImportError:
            return None

        session = onnxruntime.InferenceSession(
            fetch("onnx/model.onnx"), providers=["CPUExecutionProvider"]
        )
        names = {i.name for i in session.get_inputs()}

        def logits(ids: list[int]):
            input_ids = numpy.array([ids], dtype=numpy.int64)
            feed = {
                "input_ids": input_ids,
                "attention_mask": numpy.ones_like(input_ids),
                "token_type_ids": numpy.zeros_like(input_ids),
            }
            return session.run(None, {k: v for k, v in feed.items() if k in names})[0][0]

        return logits

    def __call__(self, text: str) -> list[Span]:
        first = self._tokenizer.encode(text)
        spans: list[Span] = []
        for window in [first, *first.overflowing]:
            predictions = self._logits(window.ids).argmax(axis=-1).tolist()
            tokens = [
                (_MODEL_LABELS.get(self._labels[token].partition("-")[2]), start, end)
                for token, (start, end) in zip(predictions, window.offsets)
            ]
            # Windows overlap, so each is decoded alone and `detect` merges them.
            spans += _decode(tokens, text)
        return spans


class NerMasker:
    """A ``Masker`` that also masks what a recognizer finds.

    Takes the same arguments as ``Masker``. ``recognizer`` is any callable that
    returns ``(entity, start, end)`` tuples and defaults to ``BertRecognizer``.
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
        self._recognizer = recognizer if recognizer is not None else BertRecognizer()
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
