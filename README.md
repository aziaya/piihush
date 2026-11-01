# piihush

[![CI](https://github.com/aziaya/piihush/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/aziaya/piihush/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-aziaya-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/aziaya)

Fast PII and secret masking for AI applications. piihush is a Rust extension for
Python that removes sensitive data from your text before it reaches an external
model provider, in RAG pipelines, AI agents, chatbots, logs and data pipelines.

```python
import piihush

piihush.mask("Call 555-123-4567 or email jane@example.com")
# 'Call [PHONE_REDACTED] or email [EMAIL_REDACTED]'
```

- **Fast:** about 26 µs for a 1 KiB chunk, roughly 10 times faster than `re`.
- **Safe on untrusted input:** matching runs in linear time, so a crafted document
  or pattern can't trigger catastrophic backtracking.
- **Context-aware:** values next to a label such as `Password:` or `Date of Birth:`
  are masked while the label stays readable, and cards, IBANs and IPv6 addresses
  are validated rather than just pattern-matched.
- **Built for pipelines:** it releases the GIL, and works with threads, `fork()`
  and pickling.
- **Local:** no network calls, no models and no runtime dependencies in the default
  install. Better name detection is an [optional add-on](#better-name-detection).

piihush reduces what reaches a model provider, but it does not catch everything.
Read [Limitations](#limitations) and [Accuracy](#accuracy) before you rely on it.

## Contents

- [Where to use it](#where-to-use-it)
- [Install](#install)
- [Quick start](#quick-start)
- [Choosing a mode](#choosing-a-mode)
- [What gets detected](#what-gets-detected)
- [Configuring a Masker](#configuring-a-masker)
- [Using piihush in a RAG pipeline](#using-piihush-in-a-rag-pipeline)
- [Using piihush with AI agents](#using-piihush-with-ai-agents)
- [Chat with any LLM privately](#chat-with-any-llm-privately)
- [Concurrency](#concurrency)
- [Better name detection](#better-name-detection)
- [API reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Accuracy](#accuracy)
- [Performance](#performance)
- [How it works](#how-it-works)
- [Contributing](#contributing)
- [Sponsor](#sponsor)
- [License](#license)

## Where to use it

| Use case | What piihush protects |
| --- | --- |
| RAG pipelines | Documents, chunks and questions before embedding or generation |
| AI agents | Tool results, memory and retrieved data before they reach the model |
| Chatbots and support assistants | Customer messages, with real values restored in the reply |
| LLM observability | Prompts and replies before they reach logs or tracing tools |
| Application logs | Emails, tokens and keys before logs are stored or shipped |
| Training data | Datasets before fine-tuning, labelling or sharing with vendors |
| Data pipelines and analytics | Free-text fields in ETL jobs and warehouses |
| Document processing | Text extracted from tickets, emails, contracts and PDFs |
| Developer tools | Code, configs and stack traces before they reach an AI assistant |

## Install

```sh
pip install piihush
```

Optional add-ons:

| Install | Adds | Works on |
| --- | --- | --- |
| `pip install "piihush[llm]"` | [Private chat](#chat-with-any-llm-privately) with any LLM provider. Needs no extra packages | Everywhere piihush does |
| `pip install "piihush[ner]"` | [Name and place detection](#better-name-detection) | Everywhere piihush does |
| `pip install "piihush[ner-fast]"` | The same, about 3 times faster | Where `onnxruntime` is available |

`piihush[llm]` also adds [LLM detection](#llm-detection), for catching more PII at a
much higher cost per record.

Wheels cover Python 3.11+ on Linux (glibc and musl), macOS and Windows, on x86-64
and ARM64. You don't need a Rust toolchain.

To build the latest code from GitHub instead, install
[Rust](https://rustup.rs/) first:

```sh
pip install git+https://github.com/aziaya/piihush
```

## Quick start

For a one-off call, use the module-level functions. They use every built-in
detector with the default settings.

```python
import piihush

piihush.mask("Password: hunter2 and SSN 123-45-6789")
# 'Password: [PASSWORD_REDACTED] and SSN [SSN_REDACTED]'

piihush.mask_batch(["Mail a@b.io", "No PII here"])
# ['Mail [EMAIL_REDACTED]', 'No PII here']

piihush.detect("Mail jane@example.com")
# [Match(entity="EMAIL", start=5, end=21, text=<16 chars>)]
```

In an application, create one `Masker` and reuse it. Creating it compiles the
patterns, which takes milliseconds. Using it is cheap and thread-safe.

```python
from piihush import Masker

masker = Masker()
masker.mask("Reach me at +44 20 7946 0958")
# 'Reach me at [PHONE_REDACTED]'
```

## Choosing a mode

| | `Masker` | `NerMasker` |
| --- | --- | --- |
| Install | `pip install piihush` | `pip install "piihush[ner]"` |
| Best for | Structured PII and secrets at high volume | Free text containing names and places |
| Time per short record | About 20 µs | About 160 ms, or 55 ms with `ner-fast` |
| Memory | About 16 MB | About 950 MB |
| Download | None | 433 MB model on first use |
| PII masked in [testing](#accuracy) | 48.6% | 69.7% |

Start with `Masker` unless your text contains names you must protect. You can also
use both: run `Masker` on everything, and `NerMasker` only on documents that need it.

## What gets detected

Run `piihush.ENTITIES` to list these names in code.

| Entity | Covers | Example input | How it's confirmed |
| --- | --- | --- | --- |
| `EMAIL` | Email addresses, including non-ASCII | `jane@example.com` | Format |
| `PHONE` | US and Canadian numbers, international numbers, and national numbers with separators | `(415) 555-2671` | Digit count and shape |
| `SSN` | US SSNs with dashes, spaces or dots | `123-45-6789` | Reserved ranges |
| `CREDIT_CARD` | Visa, Mastercard, Amex, Discover, JCB, UnionPay, Diners | `4111 1111 1111 1111` | Luhn checksum |
| `IBAN` | International bank account numbers | `DE89 3704 0044 0532 0130 00` | Mod-97 checksum |
| `IP_ADDRESS` | IPv4 and IPv6 | `192.168.1.1` | Address parsing |
| `API_KEY` | AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, Hugging Face, npm, PyPI | `AKIAIOSFODNN7EXAMPLE` | Prefix and format |
| `JWT` | JSON Web Tokens | `eyJhbGci...` | Format |
| `PRIVATE_KEY` | PEM private keys, including ones cut off by a chunk boundary | `-----BEGIN PRIVATE KEY-----` | Format |
| `ADDRESS` | Street names, UK postcodes, ZIP+4, and labelled cities and ZIP codes | `1669 Moxby Lane` | Format or label |
| `ID_NUMBER` | Account, tax, passport, license and ID numbers | `Account Number: 19359789181296` | Label required |
| `PASSWORD` | Passwords and PINs | `Password: Zh-8` | Label required |
| `DATE_OF_BIRTH` | Dates of birth | `born on April 3rd, 1997` | Label required |
| `PERSON` | Names after a title, greeting or label | `Dr. Le Grand`, `Hi Neslihan` | Label required |
| `USERNAME` | Usernames | `Username: kleppi1989` | Label required |

When a label is required, only the value is masked, so the text still makes sense:

```python
piihush.mask("Date of Birth: 17/10/1944")
# 'Date of Birth: [DATE_OF_BIRTH_REDACTED]'
```

## Configuring a Masker

### Choose entities

Pass the entities you want. The default is all of them.

```python
masker = Masker(["EMAIL", "API_KEY"])
masker.mask("a@b.io called 555-123-4567")
# '[EMAIL_REDACTED] called 555-123-4567'
```

To turn off one or two, filter the full list:

```python
masker = Masker([e for e in piihush.ENTITIES if e != "IP_ADDRESS"])
masker.mask("from 10.0.0.1, a@b.io")
# 'from 10.0.0.1, [EMAIL_REDACTED]'
```

### Add your own patterns

`custom_patterns` maps an entity name to a regular expression. Names use uppercase
letters, digits and underscores.

```python
masker = Masker(custom_patterns={"EMPLOYEE_ID": r"EMP-\d{6}"})
masker.mask("Badge EMP-123456")
# 'Badge [EMPLOYEE_ID_REDACTED]'
```

Patterns use [Rust regex syntax](https://docs.rs/regex/latest/regex/#syntax). It has
no lookaround or backreferences, which is what keeps matching linear-time.

### Mask specific values

`deny_list` maps an entity name to exact values, such as customer names or specific
email addresses. Matching ignores ASCII case and respects word boundaries, so `Ann`
doesn't match inside `Annual`.

```python
masker = Masker(deny_list={"CUSTOMER": ["Acme Corp", "Ann"]})
masker.mask("ACME CORP and Ann sent the Annual report")
# '[CUSTOMER_REDACTED] and [CUSTOMER_REDACTED] sent the Annual report'
```

### Keep specific values

`allow_list` keeps values that a detector would otherwise mask, such as your own
support address. A value must match the whole detected text. Case is ignored.

```python
masker = Masker(allow_list=["support@ourcompany.example"])
masker.mask("Write to support@ourcompany.example, not a@b.io")
# 'Write to support@ourcompany.example, not [EMAIL_REDACTED]'
```

### Change the placeholder

`template` sets the replacement text. `{entity}` becomes the entity name.

```python
Masker(template="<{entity}>").mask("a@b.io")
# '<EMAIL>'

Masker(template="***").mask("a@b.io")
# '***'
```

## Using piihush in a RAG pipeline

Mask at each point where text leaves your control.

### Mask before you chunk

A value split across two chunks can't be detected, so mask the whole document first.

```python
document = "Contact jane@example.com about the refund."

safe_document = masker.mask(document)
chunks = [safe_document[i : i + 500] for i in range(0, len(safe_document), 400)]
```

If you already have chunks, `mask_batch` is the fastest option. It keeps their order.

```python
chunks = ["First chunk, a@b.io", "Second chunk"]
safe_chunks = masker.mask_batch(chunks)
```

### Mask the user's question too

Text retrieved from your own store is only part of the prompt. Mask the question as
well, and do it before any call to an external service, including embedding APIs.

```python
question = "Why was the card 4111 1111 1111 1111 declined?"
safe_question = masker.mask(question)
```

### Use it with LangChain

piihush works with plain strings, so it needs no special integration:

```python
from langchain_core.documents import Document

documents = [Document(page_content="Mail a@b.io", metadata={"source": "crm"})]
safe_documents = [
    Document(page_content=text, metadata=doc.metadata)
    for doc, text in zip(documents, masker.mask_batch(d.page_content for d in documents))
]
```

Metadata isn't masked in this example. If yours contains PII, mask it too.

## Using piihush with AI agents

An agent passes far more data to its model than the user typed: tool results,
database rows, search hits, files and memory. Mask that data before it enters the
agent's context.

```python
def lookup_customer(customer_id):
    return "Customer: Jane Doe, jane@example.com, Card 4111 1111 1111 1111"

def safe_tool(tool, *args):
    return masker.mask(tool(*args))

safe_tool(lookup_customer, 42)
# 'Customer: [PERSON_REDACTED], [EMAIL_REDACTED], Card [CREDIT_CARD_REDACTED]'
```

When the agent must act on a real value, such as sending an email, use a
[`PrivacyGuard`](#chat-with-any-llm-privately). The model works with `[EMAIL_1]`, and
your code restores the real value at the moment a tool runs:

```python
from piihush.llm import PrivacyGuard

guard = PrivacyGuard()
context = guard.mask("Reply to jane@example.com")  # goes to the model
tool_argument = "[EMAIL_1]"                        # the model's tool call
guard.restore(tool_argument)
# 'jane@example.com'
```

Treat tool arguments from a model as untrusted. A malicious document can try to steer
an agent into using a restored value somewhere it shouldn't, so limit what each tool
can do.

## Chat with any LLM privately

`PrivateChat` masks your message, sends it to a provider, and restores the real values
in the reply. The provider only ever sees tokens such as `[EMAIL_1]`.

```sh
pip install "piihush[llm]"
```

```python
from piihush.llm import PrivateChat

chat = PrivateChat("anthropic", model="your-model-name")  # reads ANTHROPIC_API_KEY
reply = chat.send("Write a reminder to email jane@example.com")
# The provider receives: Write a reminder to email [EMAIL_1]
# You receive: a reply containing jane@example.com

for text in chat.stream("Now make it shorter"):
    print(text, end="")
```

| Provider | Name | API key variable |
| --- | --- | --- |
| OpenAI | `openai` | `OPENAI_API_KEY` |
| Claude | `anthropic` | `ANTHROPIC_API_KEY` |
| Gemini | `gemini` | `GEMINI_API_KEY` |
| DeepSeek | `deepseek` | `DEEPSEEK_API_KEY` |
| Grok | `grok` | `XAI_API_KEY` |
| Ollama | `ollama` | None |
| Ollama Cloud | `ollama-cloud` | `OLLAMA_API_KEY` |
| llama.cpp | `llamacpp` | None |

Any other OpenAI-compatible service works through `base_url`:

```python
chat = PrivateChat(base_url="http://localhost:1234/v1", model="my-model")
```

- **Options:** extra arguments go to the provider, as in
  `chat.send(prompt, temperature=0, max_tokens=200)`.
- **Better detection:** pass a guard, as in
  `PrivateChat(..., guard=PrivacyGuard(NerMasker()))`.
- **Your own client:** use `guard.mask` and `guard.restore` around any SDK, and
  `guard.restore_stream` for streaming.
- **Keep guards separate:** use one per conversation or user. A guard remembers what
  it masked, so sharing one could reveal one user's values to another.

Tested with real models: llama.cpp and Ollama Cloud. The others use each provider's
documented address and have only run against a simulated server.

## Concurrency

### Threads

A `Masker` is immutable, so one instance can be shared across threads. Scanning
releases the GIL, so threads run in parallel.

### asyncio

There is no async API, because masking is CPU work with nothing to wait for.

- **Short text:** call `mask` directly. It takes microseconds, and handing off to a
  thread would cost more than it saves.
- **Large documents or batches:** use `asyncio.to_thread`, so the event loop stays
  responsive.

```python
import asyncio

async def handle(chunks):
    return await asyncio.to_thread(masker.mask_batch, chunks)

asyncio.run(handle(["a@b.io"]))
# ['[EMAIL_REDACTED]']
```

### Batches

`mask_batch` uses every CPU core once a batch reaches 256 KiB, and a single thread
below that. Its threads exist only during the call, so there is no pool to tune.

### Multiple processes

A `Masker` can be pickled for `multiprocessing`, and `mask_batch` is safe after
`fork()`, so it works with Celery and gunicorn workers.

## Better name detection

The default `Masker` only finds a name or city when something points to it, such as
a title or label. To find them in free text, install the optional model:

```sh
pip install "piihush[ner]"
```

```python
from piihush.ner import NerMasker

ner_masker = NerMasker()  # takes the same options as Masker
ner_masker.mask("Neslihan Kaya wrote from Berlin")
# '[PERSON_REDACTED] wrote from [ADDRESS_REDACTED]'
```

`NerMasker` runs all the `Masker` rules, then adds what the model finds. Once it
finds a name, it masks that name everywhere in the same text.

- **Model:** the first run downloads
  [dslim/bert-base-NER](https://huggingface.co/dslim/bert-base-NER) (MIT, 433 MB),
  pinned to an exact revision and cached by Hugging Face.
- **Privacy:** after that download, the model runs on your machine and your text
  never leaves it.
- **Offline use:** once the model is cached, set `HF_HUB_OFFLINE=1`.
- **Speed:** the model runs on NumPy, about 160 ms per short record, so it installs
  everywhere. With `pip install "piihush[ner-fast]"` it uses `onnxruntime` instead,
  at about 55 ms with identical results. `onnxruntime` isn't available on every
  platform.
- **Memory:** about 950 MB.
- **Other models:** pass any callable that returns `(entity, start, end)` tuples,
  where the offsets are Python string indices:

```python
def my_recognizer(text):
    start = text.find("Project Falcon")
    return [("PROJECT", start, start + 14)] if start >= 0 else []

custom = NerMasker(recognizer=my_recognizer)
custom.mask("Status of Project Falcon")
# 'Status of [PROJECT_REDACTED]'
```

## LLM detection

`LlmRecognizer` asks an LLM to find PII that the rules miss. Use it with `NerMasker`,
which keeps all the rules running alongside it. The model can be local or hosted.

```python
from piihush.llm import LlmRecognizer
from piihush.ner import BertRecognizer, NerMasker, combine

llm = LlmRecognizer("ollama", model="your-model-name")

rules_and_llm = NerMasker(recognizer=llm)
strongest = NerMasker(recognizer=combine(BertRecognizer(), llm))
```

Found values are labelled `PII`, so they become `[PII_REDACTED]`.

**Before you use it:**

- **The LLM sees your raw text.** Use a model or service you trust with that data.
- **A document can talk it out of reporting.** In testing, one "ignore your
  instructions" sentence stopped the LLM reporting anything. The rules and NER model
  aren't affected, so you fall back to their results. Don't use an LLM on its own.
- **It costs far more.** Expect seconds per record, plus any provider fees.
- **It only adds masking.** A value counts only if it really appears in the text.
  If a request fails, it raises `LLMError` instead of letting text through unchecked.

## API reference

### Module functions

These use a shared `Masker` with default settings, created on first use.

| Function | Returns |
| --- | --- |
| `piihush.mask(text)` | The masked `str` |
| `piihush.mask_batch(texts)` | A `list[str]`, in input order |
| `piihush.detect(text)` | A `list[Match]`, sorted by position |
| `piihush.ENTITIES` | The names of the built-in entities |
| `piihush.__version__` | The installed version |

### `Masker`

```text
Masker(entities=None, *, custom_patterns=None, deny_list=None, allow_list=None, template=None)
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `entities` | `Sequence[str]` | All built-in entities | Built-in detectors to enable. `[]` enables none |
| `custom_patterns` | `Mapping[str, str]` | None | Entity name to regular expression |
| `deny_list` | `Mapping[str, Sequence[str]]` | None | Entity name to exact values to mask |
| `allow_list` | `Sequence[str]` | None | Exact values to keep |
| `template` | `str` | `"[{entity}_REDACTED]"` | Replacement text |

A bad configuration raises `ValueError`: an unknown entity, an invalid pattern, an
invalid entity name, or an empty deny-list value.

| Method | Returns | Notes |
| --- | --- | --- |
| `mask(text)` | `str` | Returns the same object if nothing was found |
| `mask_batch(texts)` | `list[str]` | Accepts any iterable of `str`, including generators |
| `detect(text)` | `list[Match]` | Doesn't change the text |

Passing something other than `str` raises `TypeError`, and so does passing a single
`str` to `mask_batch`.

### `Match`

| Attribute | Type | Meaning |
| --- | --- | --- |
| `entity` | `str` | Entity name |
| `start`, `end` | `int` | Python string indices, so `text[start:end]` is the value |
| `text` | `str` | The matched value |

`repr()` hides the value so it doesn't end up in your logs, but `match.text` still
holds it. Take care not to log that attribute.

### `piihush.ner.NerMasker`

Takes the same arguments as `Masker`, plus `recognizer`, and has the same `mask`,
`mask_batch` and `detect` methods. Unlike `Masker`, it can't be pickled, and
`mask_batch` handles one text at a time. Without the extra packages, it raises
`ImportError` with the install command.

## Troubleshooting

**A value wasn't masked.** Check whether it matches a format in
[What gets detected](#what-gets-detected). Add known values to `deny_list`, add a
format to `custom_patterns`, or use `NerMasker` for names and places.

**Too much was masked.** Add the value to `allow_list`, or leave out the entity that
matched it. Use `detect` to see which one that was:

```python
[m.entity for m in piihush.detect("Hi Team, mail a@b.io")]
# ['PERSON', 'EMAIL']
```

**A card number wasn't masked.** Card numbers must pass the Luhn checksum, so made-up
test numbers are often skipped. Real card numbers pass. Use `custom_patterns` if you
want every 16-digit number masked.

**`ValueError: invalid pattern`.** Rust regex has no lookaround or backreferences.

**`ImportError` from `NerMasker`.** Run `pip install "piihush[ner]"`.

## Limitations

piihush is one layer of a privacy strategy. It does not make text anonymous, and
it doesn't by itself satisfy GDPR, HIPAA or any other regulation.

- **Nothing here catches everything.** In testing, about 3 in 10 labelled values got
  past the best mode. Review the output before relying on it for sensitive data.
- **The default mode finds patterns, not meaning.** A name or city with no title,
  greeting or label around it isn't detected, and neither are medical details. Use
  `deny_list` for known values, or the [optional model](#better-name-detection) for
  free text.
- **Unlabelled numbers are mostly left alone.** A bare 9-digit SSN or account number
  looks like any other number. Use `custom_patterns` if you need them masked.
- **Harmless text is sometimes masked.** Context rules can over-match. In testing,
  1.8% of ordinary words were lost with `Masker` and 3.4% with `NerMasker`.
- **Split values can't be detected.** Mask documents before you chunk them. A private
  key whose `BEGIN` line lands in an earlier chunk is the same case.
- **Obfuscated text isn't detected,** such as `jane at example dot com` or full-width
  digits. Apply `unicodedata.normalize("NFKC", text)` first if your input may contain
  those.
- **`mask` is one-way.** Original values can't be restored from its output. Use
  [`PrivacyGuard`](#chat-with-any-llm-privately) when you need them back.
- **English is the tested language.** Other languages haven't been measured, and the
  model and most labels are English.

## Accuracy

Tested on 3,000 English records of the independent
[ai4privacy/pii-masking-400k](https://huggingface.co/datasets/ai4privacy/pii-masking-400k)
dataset, kept apart from the data used to build the rules. Each tool ran with its
defaults on the same machine. "Masked" means the exact value no longer appears in
the output.

| Tool | PII masked | Ordinary words kept | Time per record |
| --- | --- | --- | --- |
| `piihush.ner.NerMasker` | 69.7% | 96.6% | About 160 ms (55 ms with `ner-fast`) |
| Presidio 2.2 (`en_core_web_lg`) | 64.8% | 94.8% | 15 ms |
| `piihush.Masker` | 48.6% | 98.2% | About 20 µs |
| scrubadub 2.0 | 13.8% | 98.3% | 1.2 ms |
| pyveil 0.3 | 13.1% | 100% | 0.3 ms |
| pii-veil 0.1 | 10.7% | 100% | 0.2 ms |

| Masked | `Masker` | `NerMasker` | Presidio |
| --- | --- | --- | --- |
| Email | 100% | 100% | 100% |
| Phone number | 95% | 95% | 63% |
| Given name / surname | 37% / 38% | 89% / 92% | 66% / 64% |
| City | 17% | 86% | 71% |
| Street | 84% | 97% | 71% |
| ZIP or postcode | 47% | 50% | 35% |
| Social security number | 90% | 90% | 94% |
| Tax number | 83% | 83% | 96% |
| Credit card number | 29% | 29% | 84% |
| Driver's license | 51% | 51% | 84% |
| Account number | 43% | 43% | 74% |
| Date of birth | 36% | 36% | 84% |
| Username | 22% | 26% | 33% |

Read these results with care:

- **Presidio leads on many number types.** It masks many more unlabelled numbers, and
  loses more ordinary text doing so.
- **Random card numbers count against piihush.** The dataset's card numbers are
  random, so most fail the checksum piihush uses to avoid false positives.
- **The data is not everything.** It has no API keys, so it doesn't reflect piihush's
  secret detection, and pii-veil is built mainly for Polish data.
- **The test data was used more than once.** `NerMasker` was scored on it twice,
  because two leaks were fixed after the first run. Both were found by hand, on other
  text, and its score rose by 0.1 points.

To reproduce these results, see the instructions in
[`benches/accuracy.py`](benches/accuracy.py).

### LLM detection results

Measured with Qwen 2.5 1.5B running locally on 200 unused records from the same
dataset ([`benches/llm_detection.py`](benches/llm_detection.py)). Other models will
score differently.

| Setup | PII masked | Ordinary words kept | Time per record |
| --- | --- | --- | --- |
| `Masker` | 41.7% | 99.1% | 0.1 ms |
| `Masker` + LLM | 56.8% | 95.3% | 2.2 s |
| `NerMasker` | 61.8% | 96.6% | About 55 ms |
| `NerMasker` + LLM | 71.9% | 93.3% | About 2.2 s |

- **Best coverage:** `NerMasker` + LLM masked the most, at about 40 times the cost of
  `NerMasker` alone, and it replaced more ordinary text.
- **Prompt injection:** one injected sentence took the LLM from finding 40 values in
  50 records to finding 0.
- **Small sample:** with 200 records, treat small differences as noise.

## Performance

Measured with [`benches/bench.py`](benches/bench.py) on a 2016 Intel Core i7-6920HQ
(8 threads) with all detectors on, using generated text with a PII value about every
40 words. The `re` column is a smaller, roughly equivalent set of 6 patterns. Your
results will vary, so run the script on your own hardware and data.

| Input | piihush | Python `re` |
| --- | --- | --- |
| 256 B | 7.2 µs | 52 µs |
| 1 KiB | 26 µs | 271 µs |
| 4 KiB | 95 µs | 1,049 µs |
| 1 MiB | 25 ms | 221 ms |

- **Batch throughput:** 145 MB/s for `mask_batch`, compared with 29 MB/s for a
  single-threaded loop.
- **Worst case:** the slowest hostile 1 MiB input tested took 841 ms.

Where a pattern has a literal to search for, the Rust `regex`, `aho-corasick` and
`memchr` crates use SIMD (AVX2, SSSE3 or NEON), selected at runtime. Detectors also
skip the regex entirely when a required byte such as `@` is absent.

## How it works

1. Each detector scans the text. Candidates that fail validation are rejected, and
   the scan resumes inside the rejected candidate so it can't hide a real match.
2. Overlapping matches merge into one span, so no fragment of either survives.
3. The spans are replaced with placeholders. Text with nothing to mask is returned
   as the same object, without copying.

## Contributing

Bug reports and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md),
and report security issues as described in [SECURITY.md](SECURITY.md). Use only
made-up data in tests, issues and pull requests.

## Sponsor

If piihush is useful to you, you can support its development through
[GitHub Sponsors](https://github.com/sponsors/aziaya).

## License

[MIT](LICENSE)
