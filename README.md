# PR Sentinel

PR Sentinel is a public-ready Rust scaffold for deterministic GitHub pull-request merge and security risk scoring. It is deliberately a small, pure core: no network calls, credentials, wallets, deployment logic, clocks, randomness, floating point, or hidden mutable state.

## Architecture

```text
GitHub webhook / poller (host-owned)
        │ normalize and bound
        ▼
     Signals ──► score() ──► Assessment { score, reason bits, model hash }
        │                         │
        └──── head SHA ──► SentinelState::update()
                                  │
                         persist only for a new SHA
```

This boundary fits a Rialo HTTP/REX/reactive workflow: the host performs authenticated HTTP outside this crate, converts the response to `Signals`, and invokes this deterministic core. Replaying the same head SHA is a no-op even if different signals are supplied. A changed head SHA produces a new assessment and revision.

The optional `rialo` feature adds a thin adapter over the official `rialo-venus` 0.18.1 storage API. `rialo::evaluate_and_persist` accepts normalized `Signals`, a parsed `HeadSha`, and the Venus program accounts. It decodes prior workflow-PDA state with `read_from_storage`, calls the same deterministic core, and invokes `write_to_storage` only for `Update::Changed`. Invalid or unknown storage versions are treated as uninitialized, as in generated Venus workflow preflight code.

The adapter intentionally does not fetch GitHub data, build a CDK client, sign transactions, or deploy. Authentication, normalization, instruction dispatch, wallet handling, and deployment stay with the host program and operator.

## Model v1

The score is an integer in `0..=100`. Inputs above their ingestion bounds are clamped. The exact model is fingerprinted by `MODEL_HASH` (FNV-1a over a fixed specification string), so downstream state can identify the scoring rules without build-time generation.

| Signal | Weight / limit | Reason bit |
|---|---:|---:|
| Files changed | `ceil(min(n, 10,000) / 10)`, max 20; bit after 50 | 0 |
| Lines changed | `ceil(min(n, 1,000,000) / 100)`, max 20; bit after 500 | 1 |
| Binary content | +10 | 2 |
| Workflow files | +20 | 3 |
| Dependency changes | +15 | 4 |
| Permission expansion | +25 | 5 |
| Sensitive paths | +20 | 6 |
| Force push | +20 | 7 |
| Tests failed | +30 | 8 |
| Tests missing | +10 | 9 |
| First-time contributor | +5 | 10 |
| Draft | -10 | 11 |
| Approvals | -5 each, max -15 | 12 |

Flags indicate evidence, not policy verdicts. Hosts must define normalization rules (for example, which paths are sensitive), authenticate GitHub payloads, reject oversized payloads before decoding, and treat absent data as explicit `tests_missing` rather than guessing. The core accepts one aggregate PR assessment at a time and does not fetch, parse, or verify GitHub data.

## Run locally

```console
cargo test
cargo test --features rialo
cargo clippy --all-targets --all-features -- -D warnings
cargo run --bin pr-sentinel-demo
```

## Future Rialo testnet deployment

Deployment is intentionally out of scope here. A future testnet milestone should select a concrete Venus DSL instruction/WIT contract around this adapter, add golden tests that compare native and REX/WASM results, enforce HTTP response-size and execution-budget limits, and run replay/idempotency tests on a testnet. Only after those gates should a deploy manifest, funded test wallet, or authenticated GitHub secret be introduced in an operator-owned environment.
