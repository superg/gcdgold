# gcdgold development rules

## Stack

- Rust 2024, with `unsafe` forbidden.
- `clap` for the command line, Serde plus `yaml_serde` for manifests, `sha1` for legacy track identity, and `ecmlib` for CD-ROM EDC/ECC handling.
- The raw 2352-byte BIN is the only image source of truth.

## Engineering rules

- Keep extraction and building deterministic. An untouched extracted project must reproduce its source BIN byte-for-byte.
- Reject unsupported layouts explicitly; never silently preserve opaque raw sectors or guess at unknown structures.
- Manifest paths are relative to the selected data directory and must never escape it.
- Whenever full-image comparison reveals a mismatch, first isolate it and add a focused failing unit test. Only then implement the correction, retaining the test permanently.
- Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test` before completing a change.

## AI Context & Memory Protocol

### 1. Pre-Task Protocol
Before writing or modifying any code for a task:
* Read `docs/agent-memory/active_context.md` to understand current system architecture, recent changes, and active priorities.
* Read `docs/agent-memory/learned_patterns.md` to review established project conventions, structural edge cases, and technical quirks.

### 2. Post-Task Protocol (Definition of Done)
At the end of every task or feature implementation, you **must**:
1. Update `docs/agent-memory/active_context.md` with current architecture, newly supported behavior, and remaining work.
2. Append any reusable technical discoveries, edge cases, or novel implementation patterns to `docs/agent-memory/learned_patterns.md`.
