"""Measure masking latency and throughput: ``python benches/bench.py``."""

import random
import re
import statistics
import time

import piihush

WORDS = (
    "the quarterly report covers revenue growth across regions and notes that "
    "customer retention improved after support hours were extended in march"
).split()
PII = ["jane.doe@example.com", "555-123-4567", "123-45-6789", "4111 1111 1111 1111"]

# A rough pure-Python equivalent, for comparison.
PY_PATTERNS = [
    re.compile(r"[\w.%+-]+@[\w-]+(?:\.[\w-]+)*\.[a-zA-Z]{2,}"),
    re.compile(r"(?:\+?1[-. ]?)?(?:\(\d{3}\)[-. ]?|\d{3}[-. ]?)\d{3}[-. ]?\d{4}"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\b(?:AKIA[A-Z0-9]{16}|gh[pousr]_\w{36,}|sk-[\w-]{20,})"),
]


def python_mask(text):
    for pattern in PY_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def document(size, pii_every=40):
    rng = random.Random(7)
    parts, length = [], 0
    while length < size:
        token = rng.choice(PII) if len(parts) % pii_every == 39 else rng.choice(WORDS)
        parts.append(token)
        length += len(token) + 1
    return " ".join(parts)[:size]


def timed(func, arg, seconds=0.5):
    samples = []
    deadline = time.perf_counter() + seconds
    while time.perf_counter() < deadline:
        start = time.perf_counter()
        func(arg)
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def report(name, func, arg, size):
    seconds = timed(func, arg)
    print(f"{name:34} {seconds * 1e6:12.1f} us {size / seconds / 1e6:10.1f} MB/s")


def main():
    masker = piihush.Masker()
    print("single document")
    for size in (256, 1024, 4096, 1024 * 1024):
        text = document(size)
        report(f"piihush {size} B", masker.mask, text, size)
        report(f"python re {size} B", python_mask, text, size)

    clean = " ".join(WORDS) * 15
    report(f"piihush no pii {len(clean)} B", masker.mask, clean, len(clean))

    print("batch")
    docs = [document(1024) for _ in range(20_000)]
    total = sum(map(len, docs))
    report("piihush mask_batch 20k x 1 KiB", masker.mask_batch, docs, total)
    report("piihush loop 20k x 1 KiB", lambda d: [masker.mask(t) for t in d], docs, total)

    print("hostile input, 1 MiB")
    size = 1024 * 1024
    hostile = {
        "long word": "a" * size,
        "dotted run": "a." * (size // 2),
        "digits": "2" * size,
        "dashed digits": "222-" * (size // 4),
        "at signs": "a@" * (size // 2),
        "word then ats": "a" * (size // 2) + "@ " * (size // 4),
        "colons": "1:" * (size // 2),
        "plus digits": "+1 " * (size // 3),
        "dashes": "-----BEGIN " * (size // 11),
        "unterminated keys": "-----BEGIN PRIVATE KEY-----" * (size // 27),
    }
    for name, text in hostile.items():
        report(name, masker.mask, text, size)


if __name__ == "__main__":
    main()
