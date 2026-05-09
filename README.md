# pipelock-rs

**Security-critical Rust components for AI agent isolation** — featuring a 6-layer kernel-enforced process sandbox and compile-time secret redaction.

---

## What This Is

pipelock-rs implements low-level security primitives in Rust for isolating AI agents. The focus is on components where Rust's direct syscall access and type system provide significant advantages over higher-level languages.

**Core Components:**

| Component | Purpose |
|---|---|
| **pipelock-sandbox** | 6-layer process isolation using Landlock LSM, seccomp BPF, and Linux namespaces |
| **pipelock-core** | `RedactedSecret` type that enforces secret redaction at compile time |
| **pipelock-scanner** | URL scanner for credential leaks, SSRF, and injection attacks |
| **pipelock-proxy** | HTTP forward proxy with request/response scanning |
| **pipelock-recorder** | BLAKE3 hash-chained audit log |

---

## The Sandbox

The sandbox wraps untrusted processes in multiple kernel-enforced isolation layers:

| Layer | Mechanism | What It Blocks |
|---|---|---|
| Filesystem | Landlock LSM (ABI v1+) | Reads/writes outside the policy |
| Syscalls | Seccomp BPF (~130 allowed, ~400 blocked) | kexec, ptrace, mount, namespace escape |
| Capabilities | PR_CAPBSET_DROP + capset | All Linux capabilities |
| User namespace | CLONE_NEWUSER | UID/GID privilege escalation |
| Network namespace | CLONE_NEWNET | Host network access |
| PID namespace | CLONE_NEWPID + double-fork | Host process visibility |
| Mount namespace | CLONE_NEWNS | Host filesystem mount table |

**Why Rust for this?**

Go's runtime (GC, goroutine scheduler) interferes with the precise fork/exec/namespace setup required. Rust gives us:
- Direct `libc` syscall access without runtime interference
- `pre_exec` hooks that run in the child after `fork()` but before `exec()`
- Type system enforcement of one-way sandbox state transitions

---

## The RedactedSecret Type

Enforces "no secrets to disk" at compile time:

```rust
let secret = RedactedSecret::new(api_key_bytes);

//  Won't compile - no Display/Debug/Serialize
println!("{:?}", secret);  // Compile error

//  Only way to access bytes
secret.with_bytes(|bytes| {
    // Use bytes here, they never escape this closure
});

//  Serializes as placeholder
serde_json::to_string(&secret)  // → "<pl:api_key:32>"
```

The compiler proves secrets can never reach logs, recorders, or wire formats.

---

## Quickstart

```bash
# Build everything
cargo build --workspace

# Scan a URL
cargo run -p pipelock -- check --url 'https://example.com/?key=AKIAIOSFODNN7EXAMPLE'

# Start HTTP forward proxy
cargo run -p pipelock -- run --config examples/pipelock.yaml

# Route traffic through it
curl -x http://127.0.0.1:9999 https://docs.python.org/3/
```

## Using the Sandbox

```bash
# Run a command in the sandbox
cargo run -p pipelock -- sandbox echo "Hello from sandbox"

# Run a shell command
cargo run -p pipelock -- sandbox sh -c 'echo test > $TMPDIR/out.txt && cat $TMPDIR/out.txt'

# Strict mode (fails if any layer unavailable)
cargo run -p pipelock -- sandbox --strict echo "Hello"
```

The sandbox reports which layers are active:

```
[sandbox] capabilities: DROPPED
[sandbox] filesystem: ACTIVE (Landlock)
[sandbox] syscall: ACTIVE (seccomp)
[sandbox] network: ACTIVE (isolated namespace)
[sandbox] mount: ACTIVE (isolated mount namespace)
[sandbox] pid: ACTIVE (isolated PID namespace, double-fork)
[sandbox] containment: 6/6 layers active
```

---

## Project Structure

This is a Cargo workspace with 27 crates:

**Production-ready:**
- `pipelock-sandbox` — 6-layer process isolation
- `pipelock-core` — Shared types (`Verdict`, `Finding`, `RedactedSecret`)
- `pipelock-scanner` — URL scanner
- `pipelock-proxy` — HTTP forward proxy
- `pipelock-recorder` — BLAKE3 hash-chained audit log
- `pipelock-config` — YAML config loader
- `pipelock-audit` — Structured audit events

**Scaffolding (20 crates):**
The remaining crates (`pipelock-mcp`, `pipelock-rules`, `pipelock-signing`, etc.) define the workspace structure for future expansion but contain minimal implementation.

---

## Requirements

- **Linux kernel 5.13+** (for Landlock ABI v1)
- **Rust 1.80+**
- **User namespaces enabled** for full isolation: `sysctl kernel.unprivileged_userns_clone=1`

---

## Testing

```bash
# All tests
cargo test --workspace

# Sandbox integration tests (must run serially)
cargo test -p pipelock-sandbox -- --test-threads=1
```

**Note:** Integration tests require unprivileged user namespaces and will skip in CI environments (GitHub Actions, GitLab CI) where this feature is disabled.

---

## Related Projects

- **[pipelock (Go)](https://github.com/luckyPipewrench/pipelock)** — Full-featured AI agent firewall with 11-layer scanning, MCP proxy, kill switch, and more
- **[pipelab.org](https://pipelab.org)** — Documentation and guides

---

## License

Apache-2.0 — see [`LICENSE`](./LICENSE)
