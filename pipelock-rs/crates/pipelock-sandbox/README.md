# pipelock-sandbox

Rust implementation of process sandboxing for pipelock using Linux kernel security features.

## Features

- **Landlock filesystem isolation**: Restricts file access to explicitly allowed paths
- **Seccomp syscall filtering**: Blocks ~400 dangerous syscalls, allows ~130 safe ones
- **User namespaces**: Isolates process from host user/group IDs
- **Network namespaces**: Isolates network stack (strict mode only)
- **Capability dropping**: Removes all Linux capabilities
- **Resource limits**: Prevents fork bombs and disk exhaustion
- **Environment sanitization**: Provides clean, minimal environment

## Usage

### Command Line

```bash
# Best-effort mode (default) - works without user namespaces
cargo run -p pipelock -- sandbox echo "Hello from sandbox"

# With shell commands
cargo run -p pipelock -- sandbox sh -c 'echo test > $TMPDIR/test.txt && cat $TMPDIR/test.txt'

# Strict mode - requires user namespaces, fails if any layer unavailable
cargo run -p pipelock -- sandbox --strict echo "Hello"

# Custom workspace
cargo run -p pipelock -- sandbox --workspace /path/to/workspace echo "Hello"
```

### Programmatic API

```rust
use pipelock_sandbox::{launch_sandboxed, LaunchConfig};
use std::path::PathBuf;

let config = LaunchConfig {
    command: vec!["echo".to_string(), "Hello".to_string()],
    workspace: PathBuf::from("/tmp/workspace"),
    policy: None,  // Use default policy
    strict: false,
    best_effort: true,
    extra_env: vec![],
};

let status = launch_sandboxed(config)?;
assert!(status.success());
```

## Modes

### Best-Effort Mode (Default)

- Works without user namespaces
- Applies Landlock, seccomp, and rlimits
- Network isolation degraded (relies on HTTP_PROXY environment variables)
- Continues with warnings if some layers fail

### Strict Mode

- Requires user namespaces (may need `sysctl -w kernel.unprivileged_userns_clone=1`)
- All containment layers must be active
- Fails immediately if any layer unavailable
- Full network isolation with network namespace

## Security Layers

### 1. Filesystem (Landlock)

Default policy allows:
- **Read-only**: `/usr`, `/lib`, `/lib64`, `/etc/ssl`, `/etc/pki`, `/proc`
- **Read-write**: workspace directory, `/dev/shm`, per-process temp directory
- **Execute**: `/bin`, `/usr/bin`, `/usr/local/bin`, `/sbin`, `/usr/sbin`, dynamic linker paths

### 2. Syscalls (Seccomp)

- **Allowed**: ~130 syscalls (read, write, open, mmap, etc.)
- **Blocked**: ~400 dangerous syscalls (kexec, ptrace, mount, etc.)
- **Conditional**: 
  - `clone` - blocks CLONE_NEW* flags (prevents namespace escape)
  - `clone3` - blocked in strict mode (cannot inspect pointer args), allowed in best-effort
  - `socket` - blocks AF_VSOCK (VM host-guest communication)
  - `personality` - allows only safe personality types

### 3. Capabilities

All Linux capabilities dropped using:
- `PR_CAPBSET_DROP` for bounding set (0-40)
- `capset(2)` for effective/permitted/inheritable sets
- Graceful EPERM handling in user namespaces

### 4. Resource Limits

- **RLIMIT_NPROC**: 4096 processes (prevents fork bombs)
- **RLIMIT_FSIZE**: 10GB file size (prevents disk exhaustion)

### 5. Network Isolation

- **Full isolation**: Isolated network namespace with only loopback interface
- **Best-effort mode**: Relies on HTTP_PROXY environment variables (can be bypassed)

### 6. Mount Isolation

- **Full isolation**: Private mount namespace prevents mount/umount affecting host
- **Private /dev/shm**: Isolated shared memory (when mount namespace available)

**Note**: PID namespace is not used due to compatibility issues with multi-threaded applications (the first process becomes PID 1 with special restrictions that break thread creation).

## Testing

Integration tests verify kernel enforcement of all security layers. Tests must run serially due to namespace isolation:

```bash
# Run all tests (serially)
cargo test -p pipelock-sandbox -- --test-threads=1

# Run specific test
cargo test -p pipelock-sandbox test_landlock_blocks_unauthorized_read -- --test-threads=1 --nocapture
```

### Test Coverage

- ✅ Landlock blocks unauthorized file reads
- ✅ Seccomp blocks dangerous syscalls
- ✅ Network namespace isolation
- ✅ Strict mode enforcement
- ✅ Per-process temp directory
- ✅ Capabilities dropped
- ✅ Environment sanitization

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (pipelock)                                    │
│  ├─ Validates workspace                                      │
│  ├─ Probes namespace support                                 │
│  └─ Forks child with unshare(CLONE_NEWUSER | CLONE_NEWNET) │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (sandbox-init)                                 │
│  1. Drop capabilities (PR_CAPBSET_DROP + capset)            │
│  2. Configure loopback interface (if network namespace)      │
│  3. Apply Landlock filesystem policy                         │
│  4. Apply resource limits (RLIMIT_NPROC, RLIMIT_FSIZE)      │
│  5. Set no_new_privs (PR_SET_NO_NEW_PRIVS)                  │
│  6. Apply seccomp filter                                     │
│  7. Sanitize environment                                     │
│  8. exec() target command                                    │
└─────────────────────────────────────────────────────────────┘
```

## Requirements

- Linux kernel 5.13+ (for Landlock ABI v1)
- User namespaces enabled (for strict mode): `sysctl kernel.unprivileged_userns_clone=1`
- Seccomp support (CONFIG_SECCOMP=y)

## Limitations

- **Best-effort network isolation**: Without user namespaces, network isolation relies on HTTP_PROXY environment variables which can be bypassed by child processes
- **Landlock version**: Uses ABI v1 (kernel 5.13+), newer ABIs provide more features
- **Test isolation**: Integration tests must run serially (`--test-threads=1`) due to namespace isolation
- **PID namespace**: Not used due to compatibility issues with multi-threaded applications (causes thread creation failures)
- **Namespace probing removed**: The sandbox attempts namespace creation directly in pre_exec rather than probing in the parent process

## Implementation Status

✅ **Complete**:
- Seccomp filter with ~130 syscall allowlist and argument filtering for clone/socket/personality
- Namespace re-exec (user + network + mount namespaces)
- Landlock filesystem isolation
- Capability dropping with graceful EPERM handling
- Resource limits (NPROC=4096, FSIZE=10GB)
- Environment sanitization
- Integration tests (7/7 passing)
- Proper namespace creation in pre_exec (no parent process contamination)

❌ **Not Implemented**:
- PID namespace (incompatible with multi-threaded applications)

## References

- [Landlock LSM](https://landlock.io/)
- [Seccomp BPF](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [User Namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Clone Flags](https://man7.org/linux/man-pages/man2/clone.2.html)
