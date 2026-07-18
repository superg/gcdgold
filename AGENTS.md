# gcdgold development rules

## Stack

- Rust 2024, with `unsafe` forbidden.
- `clap` for the command line, Serde plus `yaml_serde` for manifests, `sha1` for legacy track identity, and `ecmlib` for CD-ROM EDC/ECC handling.
- The raw 2352-byte BIN is the only image source of truth. Do not use a cooked ISO or CUE file to extract or rebuild data.

## Engineering rules

- Keep extraction and building deterministic. An untouched extracted project must reproduce its source BIN byte-for-byte.
- Reject unsupported layouts explicitly; never silently preserve opaque raw sectors or guess at unknown structures.
- Manifest paths are relative to the selected data directory and must never escape it.
- Source hashes are informational for edited projects, but exact equality is mandatory for the untouched reference fixture.
- Whenever full-image comparison reveals a mismatch, first isolate it and add a focused failing unit test. Only then implement the correction, retaining the test permanently.
- Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test` before completing a change.

## Memory loop

At the end of every task or feature implementation:

1. Update `.agent_memory/activeContext.md` to describe the current architecture, supported behavior, and remaining work.
2. Append reusable format or implementation discoveries to `.agent_memory/learnedPatterns.md`.

