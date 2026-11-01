import multiprocessing
import pickle
import threading

import pytest
from hypothesis import given, strategies as st

import piihush
from piihush import ENTITIES, Masker, Match

CARD = "4111 1111 1111 1111"


def test_masks_the_documented_example():
    assert piihush.mask("Call 555-123-4567") == "Call [PHONE_REDACTED]"


@pytest.mark.parametrize(
    ("text", "entity"),
    [
        ("jane@example.com", "EMAIL"),
        ("555-123-4567", "PHONE"),
        ("123-45-6789", "SSN"),
        (CARD, "CREDIT_CARD"),
        ("DE89 3704 0044 0532 0130 00", "IBAN"),
        ("10.0.0.1", "IP_ADDRESS"),
        ("AKIAIOSFODNN7EXAMPLE", "API_KEY"),
        ("sk-ant-api03-abcdefghijklmnopqrstuvwxyz", "API_KEY"),
        ("ghp_" + "a" * 36, "API_KEY"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N", "JWT"),
        ("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "PRIVATE_KEY"),
    ],
)
def test_detects_each_entity_in_context(text, entity):
    assert entity in ENTITIES
    masked = piihush.mask(f"before {text} after")
    assert masked == f"before [{entity}_REDACTED] after"


def test_text_without_pii_returns_the_same_object():
    text = "nothing sensitive in here"
    assert piihush.mask(text) is text
    assert piihush.mask_batch([text])[0] is text


def test_detect_offsets_are_python_string_indices():
    text = "héllo 🌍 ñ jane@example.com, 日本語 call 555-123-4567"
    matches = piihush.detect(text)
    assert [m.entity for m in matches] == ["EMAIL", "PHONE"]
    for match in matches:
        assert text[match.start : match.end] == match.text


def test_repr_of_match_does_not_leak_the_value():
    assert "jane" not in repr(piihush.detect("jane@example.com")[0])


def test_match_equality():
    text = "a@b.io"
    assert piihush.detect(text) == piihush.detect(text)
    assert isinstance(piihush.detect(text)[0], Match)


def test_entity_selection():
    masker = Masker(["EMAIL"])
    assert masker.mask("a@b.io 555-123-4567") == "[EMAIL_REDACTED] 555-123-4567"


def test_custom_pattern_and_template():
    masker = Masker(
        [], custom_patterns={"EMPLOYEE_ID": r"EMP-\d{6}"}, template="<{entity}>"
    )
    assert masker.mask("badge EMP-123456") == "badge <EMPLOYEE_ID>"


def test_deny_and_allow_lists():
    masker = Masker(
        deny_list={"PROJECT": ["Project Falcon"], "EMAIL": ["ceo at acme"]},
        allow_list=["support@acme.com"],
    )
    masked = masker.mask("project falcon: support@acme.com, a@b.io, ceo at acme")
    assert masked == "[PROJECT_REDACTED]: support@acme.com, [EMAIL_REDACTED], [EMAIL_REDACTED]"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"entities": ["NOPE"]},
        {"custom_patterns": {"X": "("}},
        {"custom_patterns": {"lower": "a"}},
        {"deny_list": {"X": [""]}},
    ],
)
def test_invalid_config_raises_value_error(kwargs):
    with pytest.raises(ValueError):
        Masker(**kwargs)


def test_batch_preserves_order_and_accepts_generators():
    texts = [f"user{i}@example.com" if i % 2 else f"plain {i}" for i in range(5000)]
    expected = [piihush.mask(text) for text in texts]
    assert piihush.mask_batch(texts) == expected
    assert piihush.mask_batch(iter(texts)) == expected


def test_large_batch_uses_the_parallel_path():
    doc = "x" * 4096 + " a@b.io"
    assert piihush.mask_batch([doc] * 256) == ["x" * 4096 + " [EMAIL_REDACTED]"] * 256


@pytest.mark.parametrize("bad", ["a string", [1, 2], None])
def test_batch_rejects_bad_input(bad):
    with pytest.raises(TypeError):
        piihush.mask_batch(bad)


def test_rejects_non_str():
    with pytest.raises(TypeError):
        piihush.mask(b"bytes")


def test_masker_pickles_with_its_config():
    masker = Masker(
        ["EMAIL"],
        custom_patterns={"TAG": "tag-[0-9]+"},
        deny_list={"NAME": ["Zed"]},
        allow_list=["keep@me.io"],
        template="<{entity}>",
    )
    clone = pickle.loads(pickle.dumps(masker))
    text = "tag-1 Zed keep@me.io a@b.io"
    assert clone.mask(text) == masker.mask(text) == "<TAG> <NAME> keep@me.io <EMAIL>"


def test_shared_across_threads():
    masker = Masker()
    results = []
    threads = [
        threading.Thread(target=lambda: results.append(masker.mask("a@b.io")))
        for _ in range(16)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == ["[EMAIL_REDACTED]"] * 16


def _batch_in_child(queue):
    queue.put(piihush.mask_batch(["x" * 4096 + " a@b.io"] * 256)[0][-16:])


@pytest.mark.skipif(
    "fork" not in multiprocessing.get_all_start_methods(), reason="requires fork"
)
def test_parallel_batch_works_after_fork():
    # Run the parallel path first: a pool created here would deadlock the child.
    piihush.mask_batch(["x" * 4096 + " a@b.io"] * 256)
    context = multiprocessing.get_context("fork")
    queue = context.Queue()
    child = context.Process(target=_batch_in_child, args=(queue,))
    child.start()
    assert queue.get(timeout=30) == "[EMAIL_REDACTED]"
    child.join(timeout=30)


@given(st.text())
def test_any_text_round_trips_through_offsets(text):
    for match in piihush.detect(text):
        assert text[match.start : match.end] == match.text


@given(st.text())
def test_masking_is_idempotent_and_never_crashes(text):
    once = piihush.mask(text)
    assert piihush.mask(once) == once


@given(st.text(max_size=20), st.text(max_size=20))
def test_embedded_card_never_survives(prefix, suffix):
    assert CARD not in piihush.mask(f"{prefix} {CARD} {suffix}")
