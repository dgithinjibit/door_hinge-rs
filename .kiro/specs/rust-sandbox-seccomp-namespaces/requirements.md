# Requirements Document

## Introduction

This document specifies requirements for implementing seccomp BPF filtering and namespace-based process isolation in the pipelock-sandbox Rust crate. The implementation will bring the Rust sandbox to feature parity with the Go implementation (pipelock/internal/sandbox), enabling unprivileged process containment through Linux kernel primitives: seccomp (syscall restriction), user/network namespaces (isolation), and capability dropping (privilege reduction).

The sandbox applies a defense-in-depth model where multiple containment layers work together. The existing Landlock filesystem restriction is already implemented. This spec adds the remaining layers: seccomp filters to block dangerous syscalls, namespace isolation to prevent escape vectors, and a re-exec launcher pattern to apply restrictions before the target process starts.

## Glossary

- **Sandbox**: The pipelock-sandbox Rust crate that applies process containment
- **Seccomp_Filter**: A BPF (Berkeley Packet Filter) program that restricts which syscalls a process can invoke
- **BPF_Program**: The compiled bytecode representation of seccomp filter rules
- **Namespace**: A Linux kernel feature that isolates process resources (user IDs, network stack, mount points)
- **User_Namespace**: A namespace type that provides UID/GID mapping and enables unprivileged namespace creation
- **Network_Namespace**: A namespace type that isolates network interfaces and routing tables
- **Mount_Namespace**: A namespace type that isolates filesystem mount points
- **Re-exec_Launcher**: A parent process that forks a child, applies namespace isolation, then re-executes itself in sandbox-init mode
- **Sandbox_Child**: The re-executed child process that applies Landlock, seccomp, and capability restrictions before executing the target command
- **Target_Command**: The actual agent binary (Python, Node.js, Go) that runs inside the sandbox
- **Policy**: The configuration structure defining allowed filesystem paths, network access, and containment mode
- **Strict_Mode**: A containment mode that fails-closed if any sandbox layer cannot be applied
- **Best_Effort_Mode**: A containment mode that applies available layers and continues with degraded isolation when namespaces are unavailable
- **Allowlist**: A set of syscalls that are permitted by the seccomp filter
- **Denylist**: A set of syscalls that return EPERM when invoked
- **Killlist**: A set of syscalls that terminate the process (KILL_PROCESS) when invoked
- **Conditional_Filter**: A BPF instruction sequence that inspects syscall arguments to make allow/deny decisions
- **CLONE_NEW_Flags**: Syscall flags (CLONE_NEWUSER, CLONE_NEWNET, etc.) that create new namespaces
- **No_New_Privs**: A process flag (PR_SET_NO_NEW_PRIVS) that prevents privilege escalation via setuid binaries
- **Capability**: A Linux privilege unit (CAP_SYS_ADMIN, CAP_NET_ADMIN, etc.) that grants specific kernel operations
- **Architecture_Validation**: BPF check that ensures syscalls are invoked from the expected CPU architecture (x86_64)
- **AF_VSOCK**: Socket address family (40) used for VM host-guest communication, blocked to prevent namespace bypass
- **Landlock**: The existing filesystem restriction layer already implemented in the Rust sandbox
- **Seccompiler_Crate**: A Rust library that compiles structured seccomp rules into BPF bytecode
- **Nix_Crate**: A Rust library providing safe wrappers for Unix syscalls (unshare, clone, prctl)

## Requirements

### Requirement 1: Seccomp Filter Construction

**User Story:** As a sandbox operator, I want the Rust sandbox to construct seccomp BPF filters from structured rules, so that I can restrict syscalls without writing raw BPF bytecode.

#### Acceptance Criteria

1. THE Sandbox SHALL use the seccompiler crate to compile seccomp rules into BPF bytecode
2. WHEN the Sandbox constructs a filter, THE BPF_Program SHALL validate the architecture is x86_64 and terminate the process on mismatch
3. THE Sandbox SHALL define three syscall categories: allowlist (permit), denylist (EPERM), and killlist (KILL_PROCESS)
4. THE Sandbox SHALL include syscalls required by Go runtime, Python interpreter, and Node.js runtime in the allowlist
5. THE Sandbox SHALL include kernel manipulation syscalls (kexec_load, init_module, finit_module, delete_module, reboot) in the killlist
6. THE Sandbox SHALL include io_uring syscalls (io_uring_setup, io_uring_enter, io_uring_register) in the denylist to allow runtime fallback
7. THE Sandbox SHALL return EPERM for syscalls not in the allowlist, denylist, or killlist

### Requirement 2: Conditional Syscall Argument Filtering

**User Story:** As a security engineer, I want the sandbox to inspect syscall arguments for dangerous flags, so that I can block namespace creation and VM socket access while allowing safe variants.

#### Acceptance Criteria

1. WHEN the clone syscall is invoked, THE Seccomp_Filter SHALL inspect the flags argument and return EPERM if any CLONE_NEW_Flags bits are set
2. WHEN the socket syscall is invoked, THE Seccomp_Filter SHALL inspect the domain argument and return EPERM if the value equals AF_VSOCK
3. WHEN the personality syscall is invoked, THE Seccomp_Filter SHALL allow only known-safe values (0, ADDR_NO_RANDOMIZE, PER_LINUX32, query) and return EPERM for other values
4. WHERE Strict_Mode is enabled, THE Seccomp_Filter SHALL return EPERM for clone3 syscall invocations
5. WHERE Best_Effort_Mode is enabled, THE Seccomp_Filter SHALL allow clone3 syscall invocations without argument inspection

### Requirement 3: Seccomp Filter Installation

**User Story:** As a sandbox child process, I want to install the seccomp filter after setting no_new_privs, so that syscall restrictions are enforced for the target command and all its children.

#### Acceptance Criteria

1. THE Sandbox_Child SHALL set the No_New_Privs flag before installing the Seccomp_Filter
2. WHEN the Seccomp_Filter is installed, THE Sandbox SHALL use the SECCOMP_FILTER_FLAG_TSYNC flag to synchronize the filter across all threads
3. IF the seccomp syscall returns an error, THEN THE Sandbox_Child SHALL log the error reason and exit with status 1
4. WHEN the Seccomp_Filter is successfully installed, THE Sandbox SHALL log the filter size for diagnostics
5. THE Seccomp_Filter SHALL remain active for the lifetime of the process and all forked children

### Requirement 4: Namespace Creation via Re-exec Launcher

**User Story:** As a sandbox operator, I want the launcher to create user and network namespaces before executing the target command, so that the sandboxed process cannot access the host network or create new namespaces.

#### Acceptance Criteria

1. THE Re-exec_Launcher SHALL probe for user namespace support before attempting to create namespaces
2. WHEN user namespaces are available, THE Re-exec_Launcher SHALL create a child process with CLONE_NEWUSER and CLONE_NEWNET flags
3. THE Re-exec_Launcher SHALL map the current UID and GID to UID 0 and GID 0 inside the User_Namespace
4. WHERE Strict_Mode is enabled, THE Re-exec_Launcher SHALL also create a Mount_Namespace (CLONE_NEWNS flag)
5. THE Re-exec_Launcher SHALL set the Pdeathsig attribute to SIGTERM so the child is killed if the parent dies
6. THE Re-exec_Launcher SHALL create a new process group for the child to enable cleanup of all descendants
7. WHERE Best_Effort_Mode is enabled and user namespaces are unavailable, THE Re-exec_Launcher SHALL fork the child without namespace flags and set a sentinel environment variable

### Requirement 5: Sandbox Child Initialization Sequence

**User Story:** As a sandbox child process, I want to apply containment layers in the correct order, so that restrictions are enforced before the target command executes.

#### Acceptance Criteria

1. THE Sandbox_Child SHALL apply containment layers in this order: mount private /dev/shm (strict mode only), Landlock, resource limits, no_new_privs, Seccomp_Filter
2. WHEN the Sandbox_Child applies Landlock, THE Sandbox SHALL add the per-process temp directory to the Policy allowlist
3. THE Sandbox_Child SHALL report the status of each containment layer to stderr before executing the Target_Command
4. WHERE Strict_Mode is enabled and any layer fails to activate, THE Sandbox_Child SHALL exit with status 1
5. WHERE Best_Effort_Mode is enabled and a layer fails, THE Sandbox_Child SHALL log a warning and continue
6. WHEN all layers are applied, THE Sandbox_Child SHALL execute the Target_Command via syscall.Exec, replacing the child process

### Requirement 6: Capability Dropping

**User Story:** As a security engineer, I want the sandbox to drop all capabilities after namespace creation, so that the sandboxed process cannot perform privileged operations.

#### Acceptance Criteria

1. WHEN the Sandbox_Child runs inside a User_Namespace, THE Sandbox SHALL drop all capabilities from the effective, permitted, and inheritable sets
2. THE Sandbox SHALL use the prctl syscall with PR_CAPBSET_DROP to remove capabilities from the bounding set
3. THE Sandbox SHALL drop capabilities after namespace creation and before applying Landlock
4. IF capability dropping fails, THEN THE Sandbox_Child SHALL log the error and exit with status 1 in Strict_Mode
5. WHERE Best_Effort_Mode is enabled and capability dropping fails, THE Sandbox SHALL log a warning and continue

### Requirement 7: Private /dev/shm Mount (Strict Mode)

**User Story:** As a security engineer, I want strict mode to mount a private /dev/shm, so that sandboxed processes cannot access shared memory segments from other users or sandboxes.

#### Acceptance Criteria

1. WHERE Strict_Mode is enabled and a Mount_Namespace exists, THE Sandbox_Child SHALL mount a private tmpfs at /dev/shm before applying Landlock
2. THE Sandbox SHALL unmount the host /dev/shm and mount a new tmpfs with size limit of 64MB
3. IF the mount operation fails, THEN THE Sandbox_Child SHALL exit with status 1
4. WHERE Best_Effort_Mode is enabled, THE Sandbox SHALL NOT attempt to mount private /dev/shm
5. THE Sandbox SHALL log whether /dev/shm is private or shared to stderr

### Requirement 8: Per-Process Temp Directory

**User Story:** As a sandbox operator, I want each sandboxed process to have its own temp directory, so that processes cannot access each other's temporary files.

#### Acceptance Criteria

1. THE Sandbox_Child SHALL create a temp directory at /tmp/pipelock-sandbox-{PID} before applying Landlock
2. THE Sandbox_Child SHALL add the temp directory to the Policy read-write allowlist
3. THE Sandbox SHALL set the TMPDIR environment variable to the per-process temp directory
4. THE Re-exec_Launcher SHALL remove the temp directory after the Sandbox_Child exits
5. THE Sandbox SHALL NOT include /tmp in the default Landlock policy to prevent cross-sandbox access

### Requirement 9: Strict vs Best-Effort Mode Selection

**User Story:** As a sandbox operator, I want to choose between strict and best-effort modes, so that I can enforce fail-closed security in production and allow degraded isolation in constrained environments.

#### Acceptance Criteria

1. THE Sandbox SHALL support a Strict_Mode configuration flag that requires all containment layers to activate
2. THE Sandbox SHALL support a Best_Effort_Mode configuration flag that applies available layers and continues with degraded isolation
3. THE Sandbox SHALL reject configurations where both Strict_Mode and Best_Effort_Mode are enabled
4. WHERE Strict_Mode is enabled, THE Sandbox SHALL exit with status 1 if any of: Landlock, Seccomp_Filter, or Network_Namespace fail to activate
5. WHERE Best_Effort_Mode is enabled and Network_Namespace creation fails, THE Sandbox SHALL log a warning about advisory network isolation and continue

### Requirement 10: Network Namespace Loopback Configuration

**User Story:** As a sandboxed process, I want the loopback interface to be active in my network namespace, so that I can make localhost connections for inter-process communication.

#### Acceptance Criteria

1. WHEN a Network_Namespace is created, THE Sandbox_Child SHALL bring up the loopback interface (127.0.0.1) before executing the Target_Command
2. THE Sandbox SHALL use the rtnetlink protocol to configure the loopback interface
3. IF loopback configuration fails, THEN THE Sandbox_Child SHALL log a warning and continue (non-fatal)
4. WHERE Best_Effort_Mode is active and no Network_Namespace exists, THE Sandbox SHALL skip loopback configuration
5. THE Sandbox SHALL log the network namespace status (ACTIVE or DEGRADED) to stderr

### Requirement 11: Environment Variable Sanitization

**User Story:** As a sandbox operator, I want the sandbox to provide a clean environment to the target command, so that sensitive variables are not leaked and proxy settings are enforced.

#### Acceptance Criteria

1. THE Sandbox_Child SHALL construct a synthetic environment containing only: PATH, HOME, USER, TMPDIR, HTTP_PROXY, HTTPS_PROXY, NO_PROXY, and operator-specified extra variables
2. THE Sandbox SHALL remove all sandbox-internal environment variables (prefixed with __PIPELOCK_SANDBOX_) before executing the Target_Command
3. THE Sandbox SHALL set TMPDIR to the per-process temp directory
4. WHERE Best_Effort_Mode is active without Network_Namespace, THE Sandbox SHALL log a warning that HTTP_PROXY enforcement is advisory
5. THE Sandbox SHALL preserve operator-specified extra environment variables passed via the Policy

### Requirement 12: Policy Validation and Serialization

**User Story:** As a sandbox operator, I want to pass custom policies from the parent to the child process, so that I can configure filesystem rules without recompiling the sandbox.

#### Acceptance Criteria

1. THE Re-exec_Launcher SHALL serialize the Policy to JSON and pass it via environment variable to the Sandbox_Child
2. THE Sandbox_Child SHALL deserialize the Policy from the environment variable before applying Landlock
3. IF no custom Policy is provided, THEN THE Sandbox_Child SHALL use the default policy for the workspace
4. THE Sandbox SHALL validate that the Policy does not grant access to secret directories (.ssh, .aws, .gnupg, .kube, .docker) before applying Landlock
5. IF Policy validation fails, THEN THE Sandbox SHALL exit with status 1 and log the validation error

### Requirement 13: Architecture and Platform Detection

**User Story:** As a sandbox operator, I want the sandbox to detect platform support at runtime, so that I receive clear errors on unsupported systems.

#### Acceptance Criteria

1. THE Sandbox SHALL return an Unsupported error when invoked on non-Linux platforms
2. THE Sandbox SHALL return an Unsupported error when invoked on non-x86_64 architectures
3. THE Sandbox SHALL probe for user namespace support by attempting to unshare(CLONE_NEWUSER) in a test process
4. THE Sandbox SHALL detect Landlock support by checking the landlock crate's ABI negotiation result
5. THE Sandbox SHALL log the detected platform capabilities (Landlock ABI version, namespace support) at initialization

### Requirement 14: Integration with Existing Landlock Implementation

**User Story:** As a sandbox maintainer, I want the seccomp and namespace features to integrate with the existing Landlock implementation, so that all layers work together without conflicts.

#### Acceptance Criteria

1. THE Sandbox SHALL apply Landlock rules after namespace creation and before Seccomp_Filter installation
2. THE Sandbox SHALL use the existing Policy structure and validation logic from the Landlock implementation
3. THE Sandbox SHALL preserve the existing apply() function signature and error types
4. THE Sandbox SHALL extend the Policy structure with fields for deny_network and strict/best_effort mode without breaking existing callers
5. THE Sandbox SHALL maintain the existing test structure that validates policies without applying them

### Requirement 15: Comprehensive Testing Strategy

**User Story:** As a sandbox maintainer, I want comprehensive tests that verify kernel enforcement, so that I can detect regressions and validate security properties.

#### Acceptance Criteria

1. THE Sandbox SHALL include integration tests that fork child processes to test Landlock and Seccomp_Filter enforcement
2. THE Sandbox SHALL include property-based tests that verify syscall filtering for random allowlist/denylist combinations
3. THE Sandbox SHALL include tests that verify namespace isolation by attempting to access host network interfaces from inside the sandbox
4. THE Sandbox SHALL include tests that verify capability dropping by attempting privileged operations after sandbox initialization
5. THE Sandbox SHALL include tests that verify the re-exec launcher correctly passes Policy and environment variables to the child
6. THE Sandbox SHALL include tests that verify strict mode fails-closed when layers are unavailable
7. THE Sandbox SHALL include tests that verify best-effort mode continues with degraded isolation when namespaces are unavailable

### Requirement 16: Error Handling and Diagnostics

**User Story:** As a sandbox operator, I want detailed error messages when sandbox initialization fails, so that I can diagnose configuration issues and platform limitations.

#### Acceptance Criteria

1. WHEN a containment layer fails to activate, THE Sandbox SHALL log the layer name, error reason, and suggested remediation to stderr
2. THE Sandbox SHALL distinguish between fatal errors (strict mode) and warnings (best-effort mode) in log output
3. THE Sandbox SHALL report a summary of active layers (e.g., "3/3 layers active") before executing the Target_Command
4. WHERE Best_Effort_Mode is active without Network_Namespace, THE Sandbox SHALL log a warning that network isolation is advisory and can be bypassed
5. THE Sandbox SHALL return structured error types (SandboxError enum) that distinguish between Unsupported, InvalidPolicy, and kernel operation failures

### Requirement 17: Dependency Management

**User Story:** As a sandbox maintainer, I want to use well-maintained Rust crates for seccomp and namespace operations, so that I avoid reimplementing complex kernel interfaces.

#### Acceptance Criteria

1. THE Sandbox SHALL use the seccompiler crate (version 0.4 or later) for BPF filter compilation
2. THE Sandbox SHALL use the nix crate (version 0.29 or later) for unshare, clone, prctl, and capability operations
3. THE Sandbox SHALL use the libc crate for syscall number constants and architecture definitions
4. THE Sandbox SHALL use the existing landlock crate (version 0.4) for filesystem restriction
5. THE Sandbox SHALL pin dependency versions in Cargo.toml to ensure reproducible builds

### Requirement 18: Documentation and Examples

**User Story:** As a sandbox user, I want clear documentation and examples, so that I can understand how to configure and deploy the sandbox.

#### Acceptance Criteria

1. THE Sandbox SHALL include module-level documentation explaining the re-exec launcher pattern and containment layer ordering
2. THE Sandbox SHALL include doc comments for all public types (Policy, SandboxError, apply) with usage examples
3. THE Sandbox SHALL include a README.md in the crate root with quick-start examples for strict and best-effort modes
4. THE Sandbox SHALL document the differences between strict and best-effort modes in the Policy struct documentation
5. THE Sandbox SHALL document the syscall allowlist, denylist, and killlist in code comments with rationale for each category

