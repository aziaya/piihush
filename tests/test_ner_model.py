"""Runs the real model, which is a 433 MB download, so it's opt-in."""

import os

import pytest

from piihush.ner import NerMasker

pytestmark = pytest.mark.skipif(
    not os.environ.get("PIIHUSH_TEST_MODEL"), reason="set PIIHUSH_TEST_MODEL to run"
)


@pytest.fixture(scope="module")
def masker():
    return NerMasker()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Neslihan Kaya wrote from Berlin", "[PERSON_REDACTED] wrote from [ADDRESS_REDACTED]"),
        ("The quarterly report is ready", "The quarterly report is ready"),
        (
            "Neslihan Kaya emailed a@b.io about Zoë.",
            "[PERSON_REDACTED] emailed [EMAIL_REDACTED] about [PERSON_REDACTED].",
        ),
    ],
)
def test_real_model(masker, text, expected):
    assert masker.mask(text) == expected


def test_real_model_long_text_leaves_no_names(masker):
    text = " ".join(f"On day {i} Neslihan Kaya met Omar Haddad." for i in range(120))
    masked = masker.mask(text)
    assert "Neslihan" not in masked and "Haddad" not in masked
