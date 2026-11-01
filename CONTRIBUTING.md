# Contributing

## Workflow

`master` is protected, so every change goes through a pull request, including the
maintainer's.

1. Fork the repository and create a branch from `master`.
2. Make your change, with tests.
3. Open a pull request and fill in the template.
4. Once CI passes and a code owner approves, the pull request is squash-merged.

## Setup

You need Rust (stable) and [uv](https://docs.astral.sh/uv/).

```sh
cargo test                  # Rust tests, no Python needed
uv run --group dev pytest   # builds the extension, then runs the Python tests
python benches/bench.py     # speed, from an environment with a release build
python benches/accuracy.py  # accuracy, see the file for setup
```

Before opening a pull request, run `cargo fmt` and
`cargo clippy --all-targets --features python -- -D warnings`.

## Adding a detector

1. Add the entity name to `ENTITIES` and a rule to `SPECS` in `src/rules.rs`.
2. Use ASCII word boundaries (`(?-u)`). Unicode `\b` turns off the fast DFA.
3. If the format has a checksum or reserved ranges, add a validator.
4. Add tests for matches and for look-alikes that must be left alone, then add
   the new detector's hostile input to `benches/bench.py`.
5. Measure with `benches/accuracy.py --split dev`. Keep `--split heldout` for final
   scores, so results aren't tuned to the test data.

## Releasing

Update the version in `Cargo.toml` and the changelog in a pull request. After it
merges, push a `vX.Y.Z` tag from `master`.
The release workflow builds the wheels and publishes them to PyPI.

Never use real personal data in tests, issues or pull requests.
