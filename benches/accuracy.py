"""Compare masking tools on an independent labelled dataset.

Records are split in two by a hash of their ID, so the split can't be chosen by
hand. Use ``dev`` while building rules and keep ``heldout`` for final scores.

    curl -L -o benches/data/validation.parquet --create-dirs \
      https://huggingface.co/datasets/ai4privacy/pii-masking-400k/resolve/refs%2Fconvert%2Fparquet/default/validation/0000.parquet
    pip install pyarrow
    python benches/accuracy.py --tool piihush --split dev

The dataset has its own license and is not part of this repository. Other tools
must be installed separately: presidio-analyzer, presidio-anonymizer (with the
en_core_web_lg spaCy model), scrubadub, pyveil and pii-veil.
"""

import argparse
import collections
import hashlib
import re
import time


def masker_for(tool):
    if tool == "piihush":
        import piihush

        return piihush.Masker().mask
    if tool == "piihush-ner":
        from piihush.ner import NerMasker

        return NerMasker().mask
    if tool == "presidio":
        from presidio_analyzer import AnalyzerEngine
        from presidio_anonymizer import AnonymizerEngine

        analyzer, anonymizer = AnalyzerEngine(), AnonymizerEngine()

        def mask(text):
            found = analyzer.analyze(text=text, language="en")
            return anonymizer.anonymize(text=text, analyzer_results=found).text

        return mask
    if tool == "scrubadub":
        import scrubadub

        return scrubadub.Scrubber().clean
    if tool == "pyveil":
        from pyveil import Veil

        veil = Veil.high(secret=b"0" * 32, scope="bench")
        return lambda text: veil.redact_text(text).text
    if tool == "pii-veil":
        from pii_veil import Shield

        return lambda text: Shield().anonymize(text).text
    raise ValueError(tool)


def load(path, split, limit):
    import pyarrow.parquet as parquet

    columns = ["source_text", "privacy_mask", "uid", "language"]
    wanted = 1 if split == "heldout" else 0
    records = []
    for row in parquet.read_table(path, columns=columns).to_pylist():
        digest = hashlib.sha256(str(row["uid"]).encode()).hexdigest()
        if row["language"] == "en" and int(digest, 16) % 2 == wanted:
            records.append(row)
    return records[:limit]


def evaluate(mask, records):
    total, masked = collections.Counter(), collections.Counter()
    ordinary = kept = 0
    seconds = 0.0
    for record in records:
        text = record["source_text"]
        start = time.perf_counter()
        output = mask(text)
        seconds += time.perf_counter() - start

        covered = [False] * len(text)
        for span in record["privacy_mask"]:
            covered[span["start"] : span["end"]] = [True] * (span["end"] - span["start"])
            if len(span["value"]) >= 3:
                total[span["label"]] += 1
                masked[span["label"]] += span["value"] not in output
        for word in re.finditer(r"[^\W\d_]{4,}", text):
            if not any(covered[word.start() : word.end()]):
                ordinary += 1
                kept += word.group() in output
    return total, masked, ordinary, kept, seconds


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tool", default="piihush")
    parser.add_argument("--data", default="benches/data/validation.parquet")
    parser.add_argument("--split", choices=["dev", "heldout"], default="dev")
    parser.add_argument("--limit", type=int, default=3000)
    args = parser.parse_args()

    records = load(args.data, args.split, args.limit)
    total, masked, ordinary, kept, seconds = evaluate(masker_for(args.tool), records)

    print(f"{args.tool} on {len(records)} {args.split} records")
    print(f"PII masked: {sum(masked.values()) / sum(total.values()):.1%}")
    print(f"Ordinary words kept: {kept / ordinary:.1%}")
    print(f"Mean time per record: {seconds / len(records) * 1e3:.3f} ms")
    for label, count in total.most_common():
        print(f"  {label:20}{count:6}{masked[label] / count:8.0%}")


if __name__ == "__main__":
    main()
