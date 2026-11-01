import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from piihush.llm import PROVIDERS, LLMError, LlmRecognizer, PrivacyGuard, PrivateChat
from piihush.ner import NerMasker, combine

EMAIL = "jane@example.com"
PHONE = "555-123-4567"


@pytest.fixture
def server():
    """A fake OpenAI-compatible provider that records what it receives."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            state.requests.append(raw.decode())
            state.headers.append(dict(self.headers))
            body = json.loads(raw)
            if state.status != 200:
                self.send_error(state.status, "nope")
                return
            self.send_response(200)
            self.end_headers()
            if body["stream"]:
                for piece in state.pieces:
                    delta = {"choices": [{"delta": {"content": piece}}]}
                    self.wfile.write(f"data: {json.dumps(delta)}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")
            else:
                reply = {"choices": [{"message": {"content": "".join(state.pieces)}}]}
                self.wfile.write(json.dumps(reply).encode())

    class State:
        requests = []
        headers = []
        pieces = ["Hello"]
        status = 200

    state = State()
    state.requests, state.headers = [], []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    state.url = f"http://127.0.0.1:{httpd.server_port}/v1"
    yield state
    httpd.shutdown()
    httpd.server_close()


def test_guard_round_trip():
    guard = PrivacyGuard()
    masked = guard.mask(f"Mail {EMAIL} or call {PHONE}")
    assert masked == "Mail [EMAIL_1] or call [PHONE_1]"
    assert guard.restore(masked) == f"Mail {EMAIL} or call {PHONE}"


def test_same_value_gets_the_same_token():
    guard = PrivacyGuard()
    first = guard.mask(f"{EMAIL} and a@b.io and {EMAIL}")
    assert first == "[EMAIL_1] and [EMAIL_2] and [EMAIL_1]"
    assert guard.mask(f"again {EMAIL}") == "again [EMAIL_1]"


def test_unknown_tokens_stay_put():
    guard = PrivacyGuard()
    guard.mask(EMAIL)
    assert guard.restore("[EMAIL_9] [OTHER_1] [EMAIL_1]") == f"[EMAIL_9] [OTHER_1] {EMAIL}"


def test_token_already_in_the_text_is_not_reused():
    guard = PrivacyGuard()
    masked = guard.mask(f"literal [EMAIL_1] and {EMAIL}")
    assert masked == "literal [EMAIL_1] and [EMAIL_2]"
    assert guard.restore(masked) == f"literal [EMAIL_1] and {EMAIL}"


def test_guards_do_not_share_values():
    first, second = PrivacyGuard(), PrivacyGuard()
    first.mask(EMAIL)
    assert second.restore("[EMAIL_1]") == "[EMAIL_1]"


def test_reset_forgets_values():
    guard = PrivacyGuard()
    guard.mask(EMAIL)
    guard.reset()
    assert guard.restore("[EMAIL_1]") == "[EMAIL_1]"


@pytest.mark.parametrize(
    "chunks",
    [
        ["Write to [EMAIL_1] now"],
        ["Write to [", "EMAIL_", "1", "] now"],
        ["Write to [EMAIL_1", "] now"],
        list("Write to [EMAIL_1] now"),
    ],
)
def test_restore_stream_handles_split_tokens(chunks):
    guard = PrivacyGuard()
    guard.mask(EMAIL)
    assert "".join(guard.restore_stream(chunks)) == f"Write to {EMAIL} now"


def test_restore_stream_flushes_text_that_only_looks_like_a_token():
    assert "".join(PrivacyGuard().restore_stream(["array[INDEX", " is"])) == "array[INDEX is"
    assert "".join(PrivacyGuard().restore_stream(["ends with ["])) == "ends with ["


def test_works_with_a_custom_masker():
    from piihush import Masker

    guard = PrivacyGuard(Masker([], deny_list={"CUSTOMER": ["Acme"]}))
    assert guard.mask("Acme a@b.io") == "[CUSTOMER_1] a@b.io"


def test_provider_never_receives_the_values(server):
    server.pieces = ["I emailed ", "[EMAIL_1]"]
    chat = PrivateChat(base_url=server.url, model="m", system=f"Owner is {PHONE}")
    assert chat.send(f"Please email {EMAIL}") == f"I emailed {EMAIL}"
    assert chat.send(f"Also call {PHONE}")
    sent = "".join(server.requests)
    assert EMAIL not in sent and PHONE not in sent
    assert "[EMAIL_1]" in sent and "[PHONE_1]" in sent


def test_stream_restores_and_keeps_history_masked(server):
    server.pieces = ["Sent to [EM", "AIL_1]", "."]
    chat = PrivateChat(base_url=server.url, model="m")
    assert "".join(chat.stream(f"Mail {EMAIL}")) == f"Sent to {EMAIL}."
    assert chat.messages[-1] == {"role": "assistant", "content": "Sent to [EMAIL_1]."}
    assert EMAIL not in json.dumps(chat.messages)
    assert EMAIL not in server.requests[0]


def test_history_is_sent_on_the_next_turn(server):
    chat = PrivateChat(base_url=server.url, model="m")
    chat.send("one")
    chat.send("two")
    roles = [m["role"] for m in json.loads(server.requests[1])["messages"]]
    assert roles == ["user", "assistant", "user"]


def test_options_and_key_reach_the_provider(server):
    chat = PrivateChat(base_url=server.url, model="m", api_key="secret")
    chat.send("hi", temperature=0)
    assert json.loads(server.requests[0])["temperature"] == 0
    assert server.headers[0]["Authorization"] == "Bearer secret"


def test_failed_request_raises_and_keeps_history_clean(server):
    server.status = 500
    chat = PrivateChat(base_url=server.url, model="m")
    with pytest.raises(LLMError, match="500"):
        chat.send("hi")
    assert chat.messages == []


def test_unreachable_provider_raises_llm_error():
    chat = PrivateChat(base_url="http://127.0.0.1:9/v1", model="m", timeout=2)
    with pytest.raises(LLMError, match="could not reach"):
        chat.send("hi")


@pytest.mark.parametrize("provider", PROVIDERS)
def test_every_provider_is_configured(provider, monkeypatch):
    _, variable = PROVIDERS[provider]
    if variable:
        monkeypatch.delenv(variable, raising=False)
        with pytest.raises(ValueError, match=variable):
            PrivateChat(provider, "m")
        monkeypatch.setenv(variable, "key")
    assert PrivateChat(provider, "m")


@pytest.mark.parametrize(
    "kwargs", [{"provider": "nope", "model": "m"}, {"model": "m"}, {"provider": "ollama"}]
)
def test_bad_arguments_raise(kwargs):
    with pytest.raises(ValueError):
        PrivateChat(**kwargs)


def test_recognizer_returns_real_occurrences_only(server):
    server.pieces = ['["Neslihan", "Invented Name", "ab"]']
    recognizer = LlmRecognizer(base_url=server.url, model="m")
    text = "Neslihan met Neslihan"
    assert sorted(recognizer(text)) == [("PII", 0, 8), ("PII", 13, 21)]


def test_recognizer_tolerates_text_around_the_list(server):
    server.pieces = ['Sure! Here you go: ["Preston"] Hope that helps.']
    recognizer = LlmRecognizer(base_url=server.url, model="m")
    assert recognizer("From Preston") == [("PII", 5, 12)]


def test_recognizer_only_adds_to_the_rules(server):
    server.pieces = ["[]"]
    masker = NerMasker(recognizer=LlmRecognizer(base_url=server.url, model="m"))
    assert masker.mask("Neslihan a@b.io") == "Neslihan [EMAIL_REDACTED]"


def test_recognizer_masks_through_ner_masker(server):
    server.pieces = ['["Neslihan"]']
    masker = NerMasker(recognizer=LlmRecognizer(base_url=server.url, model="m"))
    assert masker.mask("Neslihan a@b.io") == "[PII_REDACTED] [EMAIL_REDACTED]"


def test_recognizer_failure_raises_instead_of_passing_text_through(server):
    server.status = 500
    masker = NerMasker(recognizer=LlmRecognizer(base_url=server.url, model="m"))
    with pytest.raises(LLMError):
        masker.mask("Neslihan a@b.io")


def test_combine_keeps_hits_from_every_recognizer():
    first = lambda text: [("PERSON", 0, 3)]
    second = lambda text: [("PII", 4, 7)]
    assert NerMasker(recognizer=combine(first, second)).mask("Ann Lee") == (
        "[PERSON_REDACTED] [PII_REDACTED]"
    )


def test_ssl_context_keeps_verification_on():
    import ssl

    from piihush.llm import _ssl_context

    context = _ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname


def test_certificate_failure_explains_the_fix(monkeypatch):
    import ssl
    import urllib.error
    import urllib.request

    def fail(*args, **kwargs):
        raise urllib.error.URLError(ssl.SSLCertVerificationError("bad"))

    monkeypatch.setattr(urllib.request, "urlopen", fail)
    with pytest.raises(LLMError, match=r"piihush\[llm\]"):
        PrivateChat(base_url="https://example.invalid/v1", model="m").send("hi")
