# Design Document: Rust Sandbox Seccomp and Namespace Isolation

## Overview

This design extends the agent-sandbox Rust crate with seccomp BPF syscall filtering, Linux namespace isolation (user, network, mount), and a re-exec launcher pattern to achieve defense-in-depth process containment. The implementation brings the Rust sandbox to feature parity with the Go pipelock implementation while leveraging Rust's type safety for compile-time correctness guarantees.

### Current State

The agent-sandbox crate currently implements:
- **Landlock V1 filesystem isolation** (kernel 5.13+)
- **Capability dropping** via prctl and capset
- **Resource limits** (RLIMIT_NPROC, RLIMIT_FSIZE)
- **Basic namespace support** (user + network namespaces)
- **Re-exec launcher pattern** for namespace creation

### Gaps to Address

1. **Landlock V1 → V5 upgrade**: Current implementation uses Landlock ABI V1. V2-V5 add critical features:
   - V2: `LANDLOCK_ACCESS_FS_REFER` (hardlink/rename across directories)
   - V3: `LANDLOCK_ACCESS_FS_TRUNCATE` (file truncation)
   - V4: Network socket bind restrictions
   - V5: `LANDLOCK_ACCESS_FS_IOCTL_DEV` (ioctl on device files)

2. **Seccomp TSYNC flag**: Ensure seccomp filter applies to all threads (critical for multi-threaded runtimes like Go)

3. **Mount namespace integration**: Add mount namespace for strict mode to isolate /dev/shm

4. **Loopback configuration**: Ensure network namespace has working loopback interface

5. **Policy validation**: Prevent accidental exposure of secret directories (.ssh, .aws, .gnupg)

### Design Goals

1. **Defense in Depth**: Multiple independent containment layers (Landlock, seccomp, namespaces, capabilities)
2. **Fail-Closed Security**: Strict mode fails if any layer cannot be applied
3. **Graceful Degradation**: Best-effort mode applies available layers and continues with warnings
4. **Type Safety**: Leverage Rust's type system to prevent configuration errors at compile time
5. **Zero Overhead**: Use zero-cost abstractions for security primitives
6. **Compatibility**: Work with Go, Python, Node.js, and other multi-threaded runtimes

## Architecture

### Containment Layers

The sandbox applies six independent containment layers in a specific order:

```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (agent-isolate)                               │
│  1. Validate workspace and policy                            │
│  2. Serialize policy to JSON                                 │
│  3. Fork child with unshare(CLONE_NEWUSER | CLONE_NEWNET)  │
│  4. Write UID/GID mappings                                   │
│  5. Wait for child exit                                      │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (sandbox-init)                                 │
│  1. Drop all capabilities (PR_CAPBSET_DROP + capset)        │
│  2. Configure loopback interface (if network namespace)      │
│  3. Mount private /dev/shm (strict mode only)               │
│  4. Apply Landlock V5 filesystem policy                      │
│  5. Apply resource limits (RLIMIT_NPROC, RLIMIT_FSIZE)      │
│  6. Set no_new_privs (PR_SET_NO_NEW_PRIVS)                  │
│  7. Apply seccomp filter with TSYNC                          │
│  8. Sanitize environment                                     │
│  9. exec() target command                                    │
└─────────────────────────────────────────────────────────────┘
```

### Layer Ordering Rationale

1. **Capabilities first**: Must drop capabilities before applying Landlock (Landlock requires CAP_SYS_ADMIN in user namespace)
2. **Loopback before Landlock**: Network configuration requires filesystem access to /sys
3. **Landlock before seccomp**: Landlock syscalls must be allowed by seccomp filter
4. **no_new_privs before seccomp**: Required by kernel for unprivileged seccomp installation
5. **Seccomp last**: Most restrictive layer, blocks syscalls needed by earlier layers

### Namespace Strategy

**User Namespace (CLONE_NEWUSER)**:
- Enables unprivileged creation of other namespaces
- Maps host UID/GID to UID 0/GID 0 inside namespace
- Provides isolated capability set
- Required for strict mode

**Network Namespace (CLONE_NEWNET)**:
- Isolates network stack (interfaces, routing, firewall)
- Provides only loopback interface (127.0.0.1)
- Prevents access to host network
- Degrades to advisory HTTP_PROXY in best-effort mode

**Mount Namespace (CLONE_NEWNS)**:
- Isolates filesystem mount table
- Enables private /dev/shm mount
- Prevents mount/umount affecting host
- Only used in strict mode

**PID Namespace (NOT USED)**:
- Incompatible with multi-threaded applications
- First process becomes PID 1 with special restrictions
- Breaks thread creation in Go, Python, Node.js
- Explicitly excluded from design

## Components and Interfaces

### 1. Seccomp Filter Builder

**Module**: `seccomp.rs`

**Responsibilities**:
- Compile structured seccomp rules into BPF bytecode
- Define syscall allowlist, denylist, and killlist
- Implement conditional argument filtering for clone, socket, personality
- Install filter with TSYNC flag

**Key Types**:

```rust
/// Seccomp filter action
#[derive(Debug, Clone, Copy)]
pub enum SeccompAction {
    Allow,           // SECCOMP_RET_ALLOW
    Errno(u16),      // SECCOMP_RET_ERRNO(n)
    Kill,            // SECCOMP_RET_KILL_PROCESS
}

/// Seccomp rule for a single syscall
#[derive(Debug, Clone)]
pub struct SeccompRule {
    pub syscall: i64,
    pub action: SeccompAction,
    pub conditions: Vec<ArgCondition>,
}

/// Argument condition for conditional filtering
#[derive(Debug, Clone)]
pub struct ArgCondition {
    pub arg_index: u8,      // 0-5 for syscall arguments
    pub operator: ArgOp,     // Eq, Ne, Gt, Lt, MaskedEq
    pub value: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum ArgOp {
    Eq,              // arg == value
    Ne,              // arg != value
    MaskedEq(u64),   // (arg & mask) == value
}
```

**Public API**:

```rust
/// Apply seccomp filter to current process
pub(crate) fn apply_seccomp(strict: bool) -> Result<(), SandboxError>;

/// Set PR_SET_NO_NEW_PRIVS (required before seccomp)
pub(crate) fn set_no_new_privs() -> Result<(), SandboxError>;
```

**Syscall Categories**:

*Allowlist* (~130 syscalls):
- File I/O: read, write, open, openat, close, lseek, pread64, pwrite64
- Memory: mmap, munmap, mprotect, brk, mremap
- Process: clone (without CLONE_NEW* flags), fork, vfork, execve, exit, exit_group
- Signals: rt_sigaction, rt_sigprocmask, rt_sigreturn, kill, tgkill
- Time: clock_gettime, gettimeofday, nanosleep
- Networking: socket (except AF_VSOCK), connect, bind, listen, accept, sendto, recvfrom
- Threading: futex, set_robust_list, get_robust_list

*Denylist* (EPERM, allows runtime fallback):
- io_uring: io_uring_setup, io_uring_enter, io_uring_register
- Async I/O: io_setup, io_submit, io_getevents

*Killlist* (KILL_PROCESS, immediate termination):
- Kernel manipulation: kexec_load, kexec_file_load, init_module, finit_module, delete_module, reboot
- Namespace creation: unshare (with CLONE_NEW* flags), setns
- Debugging: ptrace, process_vm_readv, process_vm_writev
- Privileged operations: mount, umount2, pivot_root, chroot

**Conditional Filters**:

```rust
// Block clone with CLONE_NEW* flags
SeccompRule {
    syscall: libc::SYS_clone,
    action: SeccompAction::Allow,
    conditions: vec![
        ArgCondition {
            arg_index: 0,  // flags argument
            operator: ArgOp::MaskedEq(CLONE_NEW_MASK),
            value: 0,      // No CLONE_NEW* bits set
        }
    ],
}

// Block AF_VSOCK sockets
SeccompRule {
    syscall: libc::SYS_socket,
    action: SeccompAction::Allow,
    conditions: vec![
        ArgCondition {
            arg_index: 0,  // domain argument
            operator: ArgOp::Ne,
            value: libc::AF_VSOCK as u64,
        }
    ],
}

// Allow only safe personality values
SeccompRule {
    syscall: libc::SYS_personality,
    action: SeccompAction::Allow,
    conditions: vec![
        ArgCondition {
            arg_index: 0,
            operator: ArgOp::Eq,
            value: 0,  // Query current personality
        },
        // Additional conditions for ADDR_NO_RANDOMIZE, PER_LINUX32
    ],
}
```

### 2. Namespace Manager

**Module**: `launcher.rs` (parent process), `child.rs` (child process)

**Responsibilities**:
- Probe for namespace support
- Create user, network, and mount namespaces
- Configure UID/GID mappings
- Set up loopback interface in network namespace

**Key Types**:

```rust
/// Namespace configuration
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    pub user: bool,      // CLONE_NEWUSER
    pub network: bool,   // CLONE_NEWNET
    pub mount: bool,     // CLONE_NEWNS (strict mode only)
}

/// Namespace probe result
#[derive(Debug, Clone)]
pub struct NamespaceSupport {
    pub user_ns: bool,
    pub net_ns: bool,
    pub mount_ns: bool,
}
```

**Public API**:

```rust
/// Prepare sandbox command with namespace isolation
pub fn prepare_sandbox_cmd(cfg: LaunchConfig) -> Result<Command, SandboxError>;

/// Launch sandboxed process and wait for exit
pub fn launch_sandboxed(cfg: LaunchConfig) -> Result<ExitStatus, SandboxError>;
```

**Implementation Details**:

The launcher uses Rust's `std::process::Command` with `pre_exec` hook to create namespaces:

```rust
let mut cmd = Command::new(&cfg.command[0]);
cmd.args(&cfg.command[1..]);

unsafe {
    cmd.pre_exec(move || {
        // Create namespaces
        let flags = CLONE_NEWUSER | CLONE_NEWNET | 
                   (if strict { CLONE_NEWNS } else { 0 });
        
        nix::sched::unshare(CloneFlags::from_bits_truncate(flags))?;
        
        // Write UID/GID mappings
        write_uid_map(nix::unistd::getuid())?;
        write_gid_map(nix::unistd::getgid())?;
        
        Ok(())
    });
}
```

### 3. Landlock V5 Integration

**Module**: `lib.rs` (policy), platform-specific modules

**Responsibilities**:
- Upgrade from Landlock V1 to V5
- Add support for V2-V5 access rights
- Maintain backward compatibility with older kernels

**Landlock ABI Versions**:

| ABI | Kernel | New Access Rights |
|-----|--------|-------------------|
| V1  | 5.13   | Basic file access (read, write, execute) |
| V2  | 5.19   | `LANDLOCK_ACCESS_FS_REFER` (hardlink/rename) |
| V3  | 6.2    | `LANDLOCK_ACCESS_FS_TRUNCATE` (truncate) |
| V4  | 6.7    | Network socket bind restrictions |
| V5  | 6.10   | `LANDLOCK_ACCESS_FS_IOCTL_DEV` (ioctl on devices) |

**Policy Structure**:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Read-only paths
    pub read_only: Vec<PathBuf>,
    
    /// Read-write paths
    pub read_write: Vec<PathBuf>,
    
    /// Executable paths
    pub execute: Vec<PathBuf>,
    
    /// Landlock ABI version (1-5, auto-detected)
    #[serde(default)]
    pub landlock_abi: u32,
    
    /// Deny network access (strict mode)
    #[serde(default)]
    pub deny_network: bool,
    
    /// Strict mode (fail-closed)
    #[serde(default)]
    pub strict: bool,
}
```

**Landlock V5 Access Rights**:

```rust
use landlock::*;

// V1 rights (kernel 5.13+)
const V1_READ: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    ReadFile | ReadDir
});

const V1_WRITE: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    WriteFile | RemoveDir | RemoveFile | MakeChar | MakeDir |
    MakeReg | MakeSock | MakeFifo | MakeBlock | MakeSym
});

const V1_EXECUTE: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    Execute
});

// V2 rights (kernel 5.19+)
const V2_REFER: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    Refer  // Hardlink/rename across directories
});

// V3 rights (kernel 6.2+)
const V3_TRUNCATE: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    Truncate  // Truncate files
});

// V5 rights (kernel 6.10+)
const V5_IOCTL: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    IoctlDev  // ioctl on device files
});
```

**ABI Negotiation**:

```rust
pub fn apply(policy: &Policy) -> Result<(), SandboxError> {
    // Detect highest supported ABI
    let abi = landlock::ABI::V1
        .or(landlock::ABI::V2)
        .or(landlock::ABI::V3)
        .or(landlock::ABI::V4)
        .or(landlock::ABI::V5);
    
    let mut ruleset = Ruleset::new()
        .handle_access(AccessFs::from_all(abi))?
        .create()?;
    
    // Add rules based on detected ABI
    for path in &policy.read_only {
        let mut access = V1_READ;
        if abi >= ABI::V2 {
            access |= V2_REFER;
        }
        ruleset = ruleset.add_rule(PathBeneath::new(path, access))?;
    }
    
    // Apply ruleset
    ruleset.restrict_self()?;
    
    Ok(())
}
```

### 4. Capability Manager

**Module**: `caps.rs`

**Responsibilities**:
- Drop all Linux capabilities after namespace creation
- Handle EPERM errors gracefully in user namespaces
- Verify capabilities are dropped before applying Landlock

**Key Types**:

```rust
/// Capability set type
#[derive(Debug, Clone, Copy)]
pub enum CapSet {
    Effective,
    Permitted,
    Inheritable,
    Bounding,
}
```

**Public API**:

```rust
/// Drop all capabilities from all sets
pub(crate) fn drop_all_capabilities() -> Result<(), SandboxError>;
```

**Implementation**:

```rust
pub(crate) fn drop_all_capabilities() -> Result<(), SandboxError> {
    // Drop bounding set (0-40)
    for cap in 0..=40 {
        let result = unsafe {
            libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0)
        };
        
        if result == -1 {
            let err = std::io::Error::last_os_error();
            // EINVAL means capability doesn't exist (OK)
            // EPERM in user namespace is expected (OK)
            if err.raw_os_error() != Some(libc::EINVAL) &&
               err.raw_os_error() != Some(libc::EPERM) {
                return Err(SandboxError::CapabilityDrop(err));
            }
        }
    }
    
    // Drop effective/permitted/inheritable sets
    drop_capability_sets()?;
    
    Ok(())
}

fn drop_capability_sets() -> Result<(), SandboxError> {
    use nix::sys::capability::*;
    
    let empty = CapSet::empty();
    
    capset(CapSet::Effective, &empty)?;
    capset(CapSet::Permitted, &empty)?;
    capset(CapSet::Inheritable, &empty)?;
    
    Ok(())
}
```

### 5. Network Namespace Configurator

**Module**: `netns.rs`

**Responsibilities**:
- Configure loopback interface in network namespace
- Use rtnetlink protocol for interface management
- Handle errors gracefully (non-fatal)

**Public API**:

```rust
/// Configure loopback interface (127.0.0.1) in network namespace
pub(crate) fn configure_loopback() -> Result<(), SandboxError>;
```

**Implementation**:

```rust
use rtnetlink::{new_connection, IpVersion};

pub(crate) fn configure_loopback() -> Result<(), SandboxError> {
    let (connection, handle, _) = new_connection()?;
    
    // Spawn connection handler
    tokio::spawn(connection);
    
    // Get loopback interface
    let mut links = handle.link().get().match_name("lo".to_string()).execute();
    let link = links.try_next().await?
        .ok_or(SandboxError::NetworkConfig("loopback not found".into()))?;
    
    // Bring up loopback
    handle.link().set(link.header.index).up().execute().await?;
    
    // Add 127.0.0.1/8
    handle.address()
        .add(link.header.index, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8)
        .execute()
        .await?;
    
    Ok(())
}
```

### 6. Policy Validator

**Module**: `lib.rs`

**Responsibilities**:
- Validate policy before applying Landlock
- Prevent accidental exposure of secret directories
- Ensure workspace is absolute path

**Secret Directories** (must not be in read_only or read_write):
- `~/.ssh` (SSH keys)
- `~/.aws` (AWS credentials)
- `~/.gnupg` (GPG keys)
- `~/.kube` (Kubernetes config)
- `~/.docker` (Docker credentials)
- `~/.config/gcloud` (Google Cloud credentials)

**Validation Logic**:

```rust
impl Policy {
    pub fn validate(&self) -> Result<(), SandboxError> {
        // Check for secret directories
        let secrets = [
            ".ssh", ".aws", ".gnupg", ".kube", ".docker",
            ".config/gcloud", ".azure", ".terraform.d",
        ];
        
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/root"));
        
        for path in self.read_only.iter().chain(self.read_write.iter()) {
            for secret in &secrets {
                let secret_path = home.join(secret);
                if path.starts_with(&secret_path) {
                    return Err(SandboxError::InvalidPolicy(
                        format!("Policy grants access to secret directory: {:?}", path)
                    ));
                }
            }
        }
        
        Ok(())
    }
}
```

## Data Models

### LaunchConfig

Configuration for launching a sandboxed process:

```rust
#[derive(Debug, Clone)]
pub struct LaunchConfig {
    /// Command and arguments to execute
    pub command: Vec<String>,
    
    /// Workspace directory (read-write access)
    pub workspace: PathBuf,
    
    /// Custom policy (None = use default)
    pub policy: Option<Policy>,
    
    /// Strict mode (fail-closed)
    pub strict: bool,
    
    /// Best-effort mode (graceful degradation)
    pub best_effort: bool,
    
    /// Extra environment variables
    pub extra_env: Vec<(String, String)>,
}
```

### SandboxError

Error types for sandbox operations:

```rust
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("Platform not supported: {0}")]
    Unsupported(String),
    
    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),
    
    #[error("Landlock error: {0}")]
    Landlock(#[from] landlock::RulesetError),
    
    #[error("Seccomp error: {0}")]
    Seccomp(std::io::Error),
    
    #[error("Namespace error: {0}")]
    Namespace(nix::Error),
    
    #[error("Capability drop failed: {0}")]
    CapabilityDrop(std::io::Error),
    
    #[error("Network configuration failed: {0}")]
    NetworkConfig(String),
    
    #[error("Mount failed: {0}")]
    Mount(nix::Error),
}
```

### Environment Variables

Internal environment variables for parent-child communication:

| Variable | Purpose |
|----------|---------|
| `__PIPELOCK_SANDBOX_MODE` | Set to "init" to trigger sandbox-init path |
| `__PIPELOCK_SANDBOX_POLICY` | JSON-serialized Policy |
| `__PIPELOCK_SANDBOX_WORKSPACE` | Workspace directory path |
| `__PIPELOCK_SANDBOX_STRICT` | "true" for strict mode |
| `__PIPELOCK_SANDBOX_BEST_EFFORT` | "true" for best-effort mode |

These variables are removed before executing the target command.

## Error Handling

### Strict Mode Error Handling

In strict mode, any layer failure is fatal:

```rust
if strict {
    // Landlock must be active
    apply_landlock(policy)?;
    
    // Seccomp must be active
    apply_seccomp(strict)?;
    
    // Network namespace must exist
    if !in_network_namespace() {
        return Err(SandboxError::Namespace(
            "Network namespace required in strict mode".into()
        ));
    }
    
    eprintln!("[sandbox] containment: 6/6 layers active (STRICT)");
}
```

### Best-Effort Mode Error Handling

In best-effort mode, layer failures produce warnings:

```rust
if best_effort {
    let mut active_layers = 0;
    let total_layers = 6;
    
    // Try Landlock
    match apply_landlock(policy) {
        Ok(_) => {
            eprintln!("[sandbox] filesystem: ACTIVE (Landlock)");
            active_layers += 1;
        }
        Err(e) => {
            eprintln!("[sandbox] filesystem: DEGRADED ({})", e);
        }
    }
    
    // Try seccomp
    match apply_seccomp(strict) {
        Ok(_) => {
            eprintln!("[sandbox] syscall: ACTIVE (seccomp)");
            active_layers += 1;
        }
        Err(e) => {
            eprintln!("[sandbox] syscall: DEGRADED ({})", e);
        }
    }
    
    // Check network namespace
    if in_network_namespace() {
        eprintln!("[sandbox] network: ACTIVE (isolated namespace)");
        active_layers += 1;
    } else {
        eprintln!("[sandbox] network: DEGRADED (advisory HTTP_PROXY)");
        eprintln!("[sandbox] WARNING: Network isolation is advisory and can be bypassed");
    }
    
    eprintln!("[sandbox] containment: {}/{} layers active", active_layers, total_layers);
}
```

### Error Recovery Strategies

| Error | Strict Mode | Best-Effort Mode |
|-------|-------------|------------------|
| Landlock unavailable | Exit 1 | Continue with warning |
| Seccomp unavailable | Exit 1 | Continue with warning |
| User namespace unavailable | Exit 1 | Continue without namespaces |
| Network namespace unavailable | Exit 1 | Continue with advisory HTTP_PROXY |
| Mount namespace unavailable | Exit 1 | Continue without private /dev/shm |
| Capability drop fails | Exit 1 | Continue with warning |
| Loopback config fails | Exit 1 | Continue with warning (non-fatal) |

## Testing Strategy

### Unit Tests

**Seccomp Filter Construction**:
- Test BPF bytecode generation for allowlist/denylist/killlist
- Test conditional argument filtering for clone, socket, personality
- Test architecture validation (x86_64 only)

**Policy Validation**:
- Test secret directory detection
- Test workspace path validation
- Test policy serialization/deserialization

**Capability Dropping**:
- Test capability enumeration (0-40)
- Test EPERM handling in user namespaces
- Test capability set clearing

### Integration Tests

**Landlock Enforcement**:
```rust
#[test]
fn test_landlock_blocks_unauthorized_read() {
    let workspace = tempdir().unwrap();
    let secret_file = tempdir().unwrap().path().join("secret.txt");
    fs::write(&secret_file, "secret").unwrap();
    
    let config = LaunchConfig {
        command: vec!["cat".into(), secret_file.to_str().unwrap().into()],
        workspace: workspace.path().to_path_buf(),
        policy: None,
        strict: true,
        best_effort: false,
        extra_env: vec![],
    };
    
    let status = launch_sandboxed(config).unwrap();
    assert!(!status.success());  // Should fail with EACCES
}
```

**Seccomp Enforcement**:
```rust
#[test]
fn test_seccomp_blocks_kexec() {
    let workspace = tempdir().unwrap();
    
    let config = LaunchConfig {
        command: vec![
            "python3".into(),
            "-c".into(),
            "import ctypes; ctypes.CDLL(None).syscall(246)".into(),  // kexec_load
        ],
        workspace: workspace.path().to_path_buf(),
        policy: None,
        strict: true,
        best_effort: false,
        extra_env: vec![],
    };
    
    let status = launch_sandboxed(config).unwrap();
    assert!(!status.success());  // Should be killed by seccomp
}
```

**Network Namespace Isolation**:
```rust
#[test]
fn test_network_namespace_isolation() {
    let workspace = tempdir().unwrap();
    
    let config = LaunchConfig {
        command: vec![
            "sh".into(),
            "-c".into(),
            "ip link show | grep -v lo".into(),  // Should only see loopback
        ],
        workspace: workspace.path().to_path_buf(),
        policy: None,
        strict: true,
        best_effort: false,
        extra_env: vec![],
    };
    
    let status = launch_sandboxed(config).unwrap();
    assert!(status.success());
    // Output should be empty (no non-loopback interfaces)
}
```

**Strict Mode Enforcement**:
```rust
#[test]
fn test_strict_mode_fails_without_namespaces() {
    // Disable user namespaces (requires root or sysctl)
    // This test may need to be skipped in CI
    
    let workspace = tempdir().unwrap();
    
    let config = LaunchConfig {
        command: vec!["echo".into(), "test".into()],
        workspace: workspace.path().to_path_buf(),
        policy: None,
        strict: true,
        best_effort: false,
        extra_env: vec![],
    };
    
    let result = launch_sandboxed(config);
    assert!(result.is_err());  // Should fail in strict mode
}
```

**Capability Dropping**:
```rust
#[test]
fn test_capabilities_dropped() {
    let workspace = tempdir().unwrap();
    
    let config = LaunchConfig {
        command: vec![
            "python3".into(),
            "-c".into(),
            "import os; os.setuid(0)".into(),  // Should fail without CAP_SETUID
        ],
        workspace: workspace.path().to_path_buf(),
        policy: None,
        strict: true,
        best_effort: false,
        extra_env: vec![],
    };
    
    let status = launch_sandboxed(config).unwrap();
    assert!(!status.success());  // Should fail with EPERM
}
```

### Test Configuration

All integration tests must run serially due to namespace isolation:

```bash
cargo test -p agent-sandbox -- --test-threads=1
```

Tests that require user namespaces should be skipped in CI environments:

```rust
#[test]
fn test_user_namespace_required() {
    if std::env::var("CI").is_ok() {
        eprintln!("Skipping test in CI (user namespaces disabled)");
        return;
    }
    
    // Test implementation
}
```


## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Killlist Syscall Termination

*For any* syscall in the killlist (kexec_load, init_module, finit_module, delete_module, reboot), attempting to invoke that syscall SHALL terminate the process immediately.

**Validates: Requirements 1.5**

### Property 2: Denylist Syscall Returns EPERM

*For any* syscall in the denylist (io_uring_setup, io_uring_enter, io_uring_register, io_setup, io_submit, io_getevents), attempting to invoke that syscall SHALL return EPERM without terminating the process.

**Validates: Requirements 1.6**

### Property 3: Default Deny for Uncategorized Syscalls

*For any* syscall that is not in the allowlist, denylist, or killlist, attempting to invoke that syscall SHALL return EPERM.

**Validates: Requirements 1.7**

### Property 4: Clone with Namespace Flags Blocked

*For any* clone syscall invocation where the flags argument contains any CLONE_NEW* bits (CLONE_NEWUSER, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWCGROUP), the seccomp filter SHALL return EPERM.

**Validates: Requirements 2.1**

### Property 5: AF_VSOCK Socket Creation Blocked

*For any* socket syscall invocation where the domain argument equals AF_VSOCK (40), the seccomp filter SHALL return EPERM.

**Validates: Requirements 2.2**

### Property 6: Personality Syscall Conditional Filtering

*For any* personality syscall invocation, if the argument is a known-safe value (0, ADDR_NO_RANDOMIZE, PER_LINUX32), the syscall SHALL succeed; for any other value, the seccomp filter SHALL return EPERM.

**Validates: Requirements 2.3**

### Property 7: Seccomp Filter Inheritance

*For any* process that successfully installs the seccomp filter and then forks a child process, the child process SHALL inherit the seccomp filter and be subject to the same syscall restrictions.

**Validates: Requirements 3.5**

### Property 8: Policy Serialization Round-Trip

*For any* valid Policy structure, serializing it to JSON and then deserializing it SHALL produce a Policy that is equivalent to the original (same paths, same flags, same configuration).

**Validates: Requirements 12.1, 12.2**

### Property 9: Secret Directory Validation Rejection

*For any* Policy that grants read or write access to secret directories (.ssh, .aws, .gnupg, .kube, .docker, .config/gcloud, .azure, .terraform.d), the validation function SHALL return an InvalidPolicy error.

**Validates: Requirements 12.4**


## Testing Strategy

This feature requires a dual testing approach combining property-based tests for universal correctness properties and example-based integration tests for specific scenarios and platform-dependent behavior.

### Property-Based Testing

**Library**: Use the `proptest` crate (version 1.0+) for property-based testing in Rust.

**Configuration**: Each property test MUST run a minimum of 100 iterations to ensure comprehensive input coverage.

**Test Tagging**: Each property test MUST include a comment tag referencing the design document property:

```rust
// Feature: rust-sandbox-seccomp-namespaces, Property 1: Killlist Syscall Termination
#[test]
fn prop_killlist_syscalls_terminate_process() {
    // Test implementation
}
```

**Property Test Implementation**:

1. **Property 1: Killlist Syscall Termination**
   - Generator: Random selection from killlist syscalls
   - Test: Fork child process, attempt syscall, verify process is killed (exit status indicates signal)
   - Iterations: 100 (covers all killlist syscalls multiple times)

2. **Property 2: Denylist Syscall Returns EPERM**
   - Generator: Random selection from denylist syscalls
   - Test: Fork child process, attempt syscall, verify EPERM is returned
   - Iterations: 100

3. **Property 3: Default Deny for Uncategorized Syscalls**
   - Generator: Random syscall numbers not in allowlist/denylist/killlist
   - Test: Fork child process, attempt syscall, verify EPERM is returned
   - Iterations: 100

4. **Property 4: Clone with Namespace Flags Blocked**
   - Generator: Random combinations of CLONE_NEW* flags
   - Test: Fork child process, attempt clone with generated flags, verify EPERM
   - Iterations: 100

5. **Property 5: AF_VSOCK Socket Creation Blocked**
   - Generator: Random socket types and protocols with AF_VSOCK domain
   - Test: Fork child process, attempt socket creation, verify EPERM
   - Iterations: 100

6. **Property 6: Personality Syscall Conditional Filtering**
   - Generator: Random personality values (both safe and unsafe)
   - Test: Fork child process, attempt personality syscall, verify success for safe values and EPERM for unsafe values
   - Iterations: 100

7. **Property 7: Seccomp Filter Inheritance**
   - Generator: Random allowlist syscalls (should succeed) and denylist syscalls (should fail)
   - Test: Fork child process with seccomp, fork grandchild, attempt syscall in grandchild, verify filter is active
   - Iterations: 100

8. **Property 8: Policy Serialization Round-Trip**
   - Generator: Random Policy structures with varying paths, flags, and configurations
   - Test: Serialize to JSON, deserialize, verify equality
   - Iterations: 100

9. **Property 9: Secret Directory Validation Rejection**
   - Generator: Random policies with paths that include secret directories
   - Test: Call validate(), verify InvalidPolicy error is returned
   - Iterations: 100

### Example-Based Integration Tests

Integration tests verify specific scenarios, platform behavior, and mode-dependent functionality. These tests use concrete examples rather than generated inputs.

**Test Categories**:

1. **Landlock Enforcement**:
   - Test that unauthorized file reads are blocked
   - Test that workspace directory is accessible
   - Test that per-process temp directory is accessible
   - Test that Landlock V5 features are used when available

2. **Namespace Isolation**:
   - Test that network namespace only has loopback interface
   - Test that mount namespace has private /dev/shm (strict mode)
   - Test that UID/GID mapping is correct inside user namespace
   - Test that processes cannot escape namespace isolation

3. **Capability Dropping**:
   - Test that privileged operations fail after capability dropping
   - Test that EPERM errors are handled gracefully in user namespaces
   - Test that capabilities are dropped before Landlock is applied

4. **Mode-Dependent Behavior**:
   - Test that strict mode fails when any layer is unavailable
   - Test that best-effort mode continues with warnings when layers fail
   - Test that both modes cannot be enabled simultaneously
   - Test that clone3 is blocked in strict mode and allowed in best-effort mode

5. **Environment Sanitization**:
   - Test that only allowed environment variables are present
   - Test that internal sandbox variables are removed
   - Test that TMPDIR points to per-process temp directory
   - Test that extra environment variables are preserved

6. **Error Handling**:
   - Test that layer failures produce appropriate error messages
   - Test that strict mode exits with status 1 on layer failure
   - Test that best-effort mode logs warnings and continues
   - Test that policy validation errors are reported clearly

7. **Platform Detection**:
   - Test that non-Linux platforms return Unsupported error
   - Test that non-x86_64 architectures return Unsupported error
   - Test that platform capabilities are logged at initialization

8. **Cleanup and Resource Management**:
   - Test that per-process temp directory is removed after exit
   - Test that child processes are killed when parent dies (Pdeathsig)
   - Test that process groups enable cleanup of all descendants

### Test Execution Requirements

**Serial Execution**: All integration tests MUST run serially due to namespace isolation:

```bash
cargo test -p agent-sandbox -- --test-threads=1
```

**CI Environment Handling**: Tests requiring user namespaces SHOULD be skipped in CI environments where this feature is disabled:

```rust
#[test]
fn test_requiring_user_namespace() {
    if std::env::var("CI").is_ok() {
        eprintln!("Skipping test in CI (user namespaces disabled)");
        return;
    }
    // Test implementation
}
```

**Test Isolation**: Each test MUST use a unique workspace directory to prevent interference:

```rust
use tempfile::tempdir;

#[test]
fn test_example() {
    let workspace = tempdir().unwrap();
    // Use workspace.path() for test
}
```

### Test Coverage Goals

- **Property-based tests**: 9 properties × 100 iterations = 900 test cases
- **Integration tests**: ~30 example-based tests covering specific scenarios
- **Code coverage**: Target 80%+ line coverage for sandbox implementation
- **Platform coverage**: Test on Linux kernel 5.13+ (Landlock V1), 5.19+ (V2), 6.2+ (V3), 6.10+ (V5)

### Testing Limitations

**Cannot Test**:
- Actual kernel enforcement on non-Linux platforms (use mocks or skip tests)
- Behavior on architectures other than x86_64 (use architecture detection)
- User namespace availability in restricted environments (skip tests gracefully)
- PID namespace behavior (explicitly excluded from design)

**Workarounds**:
- Use Docker containers with user namespace support for CI testing
- Mock platform detection functions for cross-platform testing
- Use feature flags to conditionally compile platform-specific code
- Document manual testing procedures for environments where automated tests cannot run

