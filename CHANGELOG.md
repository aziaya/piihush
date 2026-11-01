# Changelog

This project follows [Semantic Versioning](https://semver.org/).

## 0.1.1 - 2026-11-01

- `piihush[ner]` no longer needs `onnxruntime`, so it installs on every supported
  platform and Python version. The model now runs on NumPy with identical results.
  It is about twice as slow as before.
- `OnnxRecognizer` is replaced by `BertRecognizer`.

## 0.1.0 - 2026-11-01

Initial release: detectors for email, phone, SSN, credit card, IBAN, IP address,
API key, JWT, private key, ID number, password, date of birth, address, person and
username, with custom patterns, deny and allow lists, and parallel batch masking.
Optional model-based name and place detection through `piihush[ner]`.
