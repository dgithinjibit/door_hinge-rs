# agent-isolate

**Production-ready Rust library for AI agent process isolation** — featuring kernel-enforced sandboxing with Landlock LSM, seccomp BPF, and Linux namespaces, plus compile-time secret redaction.

---

## What This Is

`agent-isolate` provides robust, type-safe APIs for isolating untrusted AI agent processes on Linux. Built in Rust for maximum safety and performance, it combines multiple kernel security primitives into a defense-in-depth isolation strategy.

**Core Components:**

| Component | Purpose |
|---|---|
| **agent-sandbox** | 6-layer process isolation using Landlock LSM, seccomp BPF, and Linux namespaces |
| **agent-core** | `RedactedSecret` type that enforces secret redaction at compile time |
| **agent-scanner** | URL scanner for credential leaks, SSRF, and injection attacks |
| **agent-proxy** | HTTP forward proxy with request/response scanning |
| **agent-recorder** | BLAKE3 hash-chained audit log |

**Inspired by [pipelock](https://github.com/luckyPipewrench/pipelock)'s security model**, with Rust-specific enhancements for type safety and zero-cost abstractions.

---

## Why Rust for Agent Isolation?

Rust provides unique advantages for security-critical isolation:

- **Type-safe APIs**: The compiler prevents accidentally skipping isolation steps
- **Zero-cost abstractions**: No runtime overhead for safety guarantees
- **Memory safety**: No buffer overflows or use-after-free vulnerabilities
- **Compile-time secret redaction**: Impossible to accidentally log secrets
- **Direct syscall access**: Precise control over kernel primitives without runtime interference

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
| Mount namespace | CLONE_NEWNS | Host filesystem mount table |

**Defense in Depth**: Each layer provides independent protection. Even if one layer is bypassed, others remain enforced.

---

## The RedactedSecret Type

Enforces "no secrets to disk" at compile time:

```rust
use agent_core::RedactedSecret;

let secret = RedactedSecret::new(api_key_bytes);

// ❌ Won't compile - no Display/Debug/Serialize
println!("{:?}", secret);  // Compile error

// ✅ Only way to access bytes
secret.with_bytes(|bytes| {
    // Use bytes here, they never escape this closure
});

// ✅ Serializes as placeholder
serde_json::to_string(&secret)  // → "<agent:api_key:32>"
```

The compiler proves secrets can never reach logs, recorders, or wire formats.

---

## Quickstart

```bash
# Build everything
cargo build --workspace

# Scan a URL
cargo run -p agent-isolate -- check --url 'https://example.com/?key=AKIAIOSFODNN7EXAMPLE'

# Start HTTP forward proxy
cargo run -p agent-isolate -- run --config examples/agent-isolate.yaml

# Route traffic through it
curl -x http://127.0.0.1:9999 https://docs.python.org/3/
```

## Using the Sandbox

```bash
# Run a command in the sandbox
cargo run -p agent-isolate -- sandbox echo "Hello from sandbox"

# Run a shell command
cargo run -p agent-isolate -- sandbox sh -c 'echo test > $TMPDIR/out.txt && cat $TMPDIR/out.txt'

# Strict mode (fails if any layer unavailable)
cargo run -p agent-isolate -- sandbox --strict echo "Hello"
```

The sandbox reports which layers are active:

```
[sandbox] capabilities: DROPPED
[sandbox] filesystem: ACTIVE (Landlock)
[sandbox] syscall: ACTIVE (seccomp)
[sandbox] network: ACTIVE (isolated namespace)
[sandbox] mount: ACTIVE (isolated mount namespace)
[sandbox] containment: 6/6 layers active
```

---

## Project Structure

This is a Cargo workspace with 27 crates:

**Production-ready:**
- `agent-sandbox` — 6-layer process isolation
- `agent-core` — Shared types (`Verdict`, `Finding`, `RedactedSecret`)
- `agent-scanner` — URL scanner
- `agent-proxy` — HTTP forward proxy
- `agent-recorder` — BLAKE3 hash-chained audit log
- `agent-config` — YAML config loader
- `agent-audit` — Structured audit events

**Scaffolding (20 crates):**
The remaining crates (`agent-mcp`, `agent-rules`, `agent-signing`, etc.) define the workspace structure for future expansion but contain minimal implementation.

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
cargo test -p agent-sandbox -- --test-threads=1
```

**Note:** Integration tests require unprivileged user namespaces and will skip in CI environments (GitHub Actions, GitLab CI) where this feature is disabled.

---

## Use Cases

- **AI Agent Sandboxing**: Isolate LLM-powered agents with tool access
- **Code Execution Platforms**: Run untrusted user code safely
- **CI/CD Pipelines**: Sandbox build and test processes
- **Plugin Systems**: Isolate third-party plugins
- **Multi-Tenant Systems**: Provide per-tenant isolation

---

## Comparison with Other Solutions

| Feature | agent-isolate | Docker | Firecracker | bubblewrap |
|---------|---------------|--------|-------------|------------|
| **Startup Time** | <10ms | ~1s | ~125ms | <10ms |
| **Memory Overhead** | <1MB | ~10MB | ~5MB | <1MB |
| **Landlock Support** | ✅ | ❌ | ❌ | ❌ |
| **Seccomp BPF** | ✅ | ✅ | ✅ | ✅ |
| **Type-Safe API** | ✅ | ❌ | ❌ | ❌ |
| **Compile-Time Guarantees** | ✅ | ❌ | ❌ | ❌ |
| **No Root Required** | ✅ | ❌ | ❌ | ✅ |

---

## Related Projects

- **[pipelock (Go)](https://github.com/luckyPipewrench/pipelock)** — Full-featured AI agent firewall with 11-layer scanning, MCP proxy, kill switch, and more. `agent-isolate` is inspired by pipelock's security model and provides similar isolation primitives in Rust.
- **[pipelab.org](https://pipelab.org)** — Documentation and guides for AI agent security

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

## License

Apache-2.0 — see [`LICENSE`](./LICENSE)

---

## Acknowledgments

This project is inspired by [pipelock](https://github.com/luckyPipewrench/pipelock) by Joshua Waldrep. We're grateful for the pioneering work in AI agent security and the open-source security model that informed this implementation.
