import pytest

from piihush import Match
from piihush.ner import NerMasker, _decode


def recognizer(text):
    for name, entity in (("Neslihan", "PERSON"), ("Preston", "ADDRESS")):
        start = text.find(name)
        if start >= 0:
            yield entity, start, start + len(name)


def masker(**kwargs):
    return NerMasker(recognizer=recognizer, **kwargs)


def test_combines_model_and_rule_hits():
    text = "Neslihan from Preston, a@b.io"
    assert masker().mask(text) == "[PERSON_REDACTED] from [ADDRESS_REDACTED], [EMAIL_REDACTED]"


def test_offsets_index_the_python_string():
    text = "日本語 🌍 Neslihan a@b.io"
    matches = masker().detect(text)
    assert [m.entity for m in matches] == ["PERSON", "EMAIL"]
    for match in matches:
        assert isinstance(match, Match)
        assert text[match.start : match.end] == match.text


def test_overlap_with_rule_hit_leaves_no_fragment():
    # The email rule and the recognizer both claim part of this address.
    assert masker().mask("Neslihan@example.org") == "[EMAIL_REDACTED]"


def test_entities_limit_model_hits():
    assert masker(entities=["EMAIL"]).mask("Neslihan a@b.io") == "Neslihan [EMAIL_REDACTED]"


def test_allow_list_applies_to_model_hits():
    assert masker(allow_list=["preston"]).mask("Preston") == "Preston"


def test_template_and_batch():
    assert masker(template="<{entity}>").mask_batch(["Neslihan", "plain"]) == ["<PERSON>", "plain"]


def test_decode_covers_the_whole_word():
    assert _decode([("PERSON", 6, 7)], "about Zoë now") == [("PERSON", 6, 9)]


def test_decode_joins_adjacent_tokens_only():
    text = "Ann Lee and Bob"
    tokens = [("PERSON", 0, 3), ("PERSON", 4, 7), (None, 8, 11), ("PERSON", 12, 15)]
    assert _decode(tokens, text) == [("PERSON", 0, 7), ("PERSON", 12, 15)]


def test_overlapping_window_hits_merge():
    def windows(text):
        return [("PERSON", 0, 8), ("PERSON", 0, 8), ("PERSON", 9, 17)]

    masked = NerMasker(recognizer=windows).mask("Neslihan Neslihan")
    assert masked == "[PERSON_REDACTED] [PERSON_REDACTED]"


def test_a_name_found_once_is_masked_everywhere():
    def first_only(text):
        return [("PERSON", 0, 13)]

    masked = NerMasker(recognizer=first_only).mask("Neslihan Kaya met Kaya and Neslihan, not Kayak")
    assert masked == (
        "[PERSON_REDACTED] met [PERSON_REDACTED] and [PERSON_REDACTED], not Kayak"
    )


def test_repeats_respect_the_allow_list():
    def first_only(text):
        return [("PERSON", 0, 8)]

    masked = NerMasker(recognizer=first_only, allow_list=["Kaya"]).mask("Ann Kaya met Kaya")
    assert masked == "[PERSON_REDACTED] met Kaya"


def test_missing_packages_explain_the_extra(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "tokenizers":
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ImportError, match=r"piihush\[ner\]"):
        NerMasker()
