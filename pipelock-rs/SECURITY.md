# Security Policy

`pipelock-rs` is an experimental Rust port of [pipelock](https://github.com/dgithinjibit/pipelock).
The same security model applies, with one Rust-specific addition: the
`RedactedSecret` type in `pipelock-core` enforces "no agent secrets to disk
or log" through the type system, not by convention.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report privately via [GitHub Security Advisories](https://github.com/dgithinjibit/pipelock/security/advisories/new)
on the upstream repo (this port shares the same threat model).

Include:
- Description and impact
- Steps to reproduce
- A minimal reproducer if possible
- Suggested fix, if any

## Response timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 1 week
- **Coordinated disclosure:** typically within 30 days, in agreement with the reporter

## In scope

- Bypass of URL scanning (length, scheme, CRLF, traversal, blocklist, allowlist, DLP, SSRF)
- A path that lets the bytes wrapped by `RedactedSecret` reach disk, the
  network, a log, or any `serde` output as anything other than the
  `<pl:class:len>` placeholder
- Bypass of the BLAKE3 hash chain in `pipelock-recorder` such that record
  tampering is not detected by `verify_chain`
- Fail-open behavior on the proxy edge — any error path that silently allows
  a request that should have been blocked
- SSRF reaching loopback / RFC1918 / link-local / cloud-metadata / IPv6
  ULA / IPv6 link-local / unspecified addresses through the proxy
- Sandbox escape from a process subjected to `pipelock-sandbox::apply` on a
  Linux kernel with Landlock enabled (note: seccomp + namespace re-exec is
  documented as **not yet implemented** — that's a known limitation, not a
  vulnerability)
- Audit log injection or log tampering
- Config parsing crashes or memory corruption from untrusted YAML

## Out of scope

- Anything depending on a feature still marked "deferred" in
  [`STATUS.md`](./STATUS.md) (TLS interception, MCP, response scanning, hot
  reload, kill switch, signing, etc.). These are scaffolding only.
- DoS via legitimately heavy traffic.
- Issues in dependencies that don't affect `pipelock-rs` directly — please
  report those upstream.

## Supported versions

This crate is `0.0.x` and does not yet offer a stability guarantee. Always
run from `main` for security fixes.

## Security invariants (must be proven by tests)

These are the load-bearing invariants — if you find a path that violates one
of them, that's a vulnerability:

1. **Fail-closed at the proxy edge.** Any error during scan or forwarding
   collapses to `Action::Block` with status 403 and `x-pipelock-blocked: 1`.
2. **Content scanning runs before DNS resolution.** Layers 1–6 (length,
   scheme, CRLF, traversal, blocklist, DLP) execute before SSRF/DNS so DNS
   itself can't be used as an exfiltration channel.
3. **`RedactedSecret` is one-way.** Bytes go in via `new()`. They come back
   out only via the closure-borrowed `with_bytes` (which cannot leak the
   slice past the closure body, by lifetime). `Display`, `Debug`,
   `Serialize` all produce `<pl:class:len>`. No `Deserialize` is implemented.
4. **Hash chain verifies linearly.** `verify_chain` walks every record and
   recomputes the BLAKE3 of the serialized form; any tampered record breaks
   the chain at the next link.
5. **`unsafe_code = "forbid"`** at the workspace level. Any new `unsafe`
   block is a CI failure.
