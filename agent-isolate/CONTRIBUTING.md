# Contributing to agent-rs

Thanks for considering a contribution. `agent-rs` is an experimental
Rust port; the public-facing surface is small and we want to keep it
boring, fast, and provably safe before adding scope.

## Before you start

Read [`STATUS.md`](./STATUS.md). It lists exactly what's done, what's a
documented stub, and what's deferred. If your idea matches a stub, that's
the most useful place to spend effort. If it's outside the listed phases,
open an issue first — we'd rather agree on the shape before you write code.

The longer-term architecture lives in [`PORT_PLAN.md`](./PORT_PLAN.md).
Section §1 is the "why Rust" list; please don't propose features that
duplicate work already done well in the Go version.

## Development setup

```bash
# Toolchain
rustup default stable
rustup component add rustfmt clippy

# Build, test, lint — all three must pass before pushing
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

MSRV is **1.80**. Don't use features stabilized after that.

## Hard rules

These are non-negotiable; violating any of them breaks the security model:

- **No `unsafe` code.** The workspace lints set `unsafe_code = "forbid"`.
  If you think you need `unsafe`, open an issue first.
- **No fail-open paths.** Any error during scan or forward must collapse to
  `Action::Block` at the proxy edge. Tests for this live in
  `agent-proxy/tests/proxy_e2e.rs` and the per-layer tests in
  `agent-scanner`.
- **DLP runs before SSRF/DNS.** Reordering these would make DNS itself a
  data-exfiltration channel. The order is documented in
  `agent-scanner/src/lib.rs` and verified by the scanner tests.
- **No raw secret bytes outside `RedactedSecret`.** Once a scanner captures
  matched bytes, they go straight into a `RedactedSecret`. There must be no
  path from there to a logger, recorder, or `serde` output that produces
  anything other than the `<pl:class:len>` placeholder. The compiler
  enforces this — please don't try to work around it.
- **No `unwrap`/`expect`/`panic` on runtime input.** The clippy lints
  `unwrap_used`, `expect_used`, `panic`, `todo`, `dbg_macro` are all
  warn-by-default. CI runs with `-D warnings`. If you genuinely need
  `expect` (e.g. for a compile-time-constant regex), gate it with a
  targeted `#[allow(clippy::expect_used)]` and a comment explaining why
  the failure mode is a programming error, not user input.

## Style

- `rustfmt` defaults plus `max_width = 100`. CI checks formatting.
- Default to writing **no comments**. Add a comment only when the *why* is
  non-obvious from the code (a hidden constraint, a workaround, a design
  invariant). Don't restate what the code does.
- Don't add abstractions for hypothetical future requirements. Three
  similar lines beats a premature trait.
- New code must come with a test that would have caught the bug in its
  absence. Security-relevant changes need a regression test that exercises
  the bypass attempt, not just the happy path.

## Pull request checklist

Before opening a PR:

- [ ] `cargo fmt --all -- --check` clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo test --workspace` green
- [ ] `cargo build --workspace --release` succeeds
- [ ] If you added a new crate or feature: README, `STATUS.md`, and (if
      relevant) `PORT_PLAN.md` updated
- [ ] If you touched a security invariant: a test that would catch a
      regression of the invariant, not just the happy path
- [ ] Commit messages follow the pattern `crate: short description`

PRs are squash-merged. Keep the description focused on **why** — what the
diff does is in the diff itself.

## Reporting a vulnerability

See [`SECURITY.md`](./SECURITY.md). Don't open a public issue.

## License

By contributing you agree your work is licensed under the Apache License
2.0 (see [`LICENSE`](./LICENSE)).
