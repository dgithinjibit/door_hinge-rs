# Implementation Plan: Rust Sandbox Seccomp and Namespace Isolation

## Overview

This implementation plan breaks down the seccomp BPF filtering and namespace-based process isolation feature into discrete coding tasks. The implementation follows a 6-layer containment model with defense-in-depth security: capabilities, network namespace loopback, mount namespace (strict mode), Landlock V5 filesystem isolation, resource limits, and seccomp syscall filtering.

The tasks are organized to build incrementally, with early validation through property-based tests (proptest, 100 iterations) and integration tests. Each task references specific requirements for traceability.

## Tasks

- [x] 1. Upgrade Landlock from V1 to V5 with ABI negotiation
  - [x] 1.1 Update landlock crate dependency to 0.4+ in Cargo.toml
    - Add landlock = "0.4" to dependencies
    - Update any deprecated API usage from V1 implementation
    - _Requirements: 14.4, 17.4_

  - [x] 1.2 Implement Landlock V2-V5 access rights in lib.rs
    - Define V2_REFER (hardlink/rename), V3_TRUNCATE, V5_IOCTL access rights
    - Implement ABI negotiation logic to detect highest supported version
    - Update apply() function to use detected ABI version
    - _Requirements: 14.1, 14.2_

  - [ ]* 1.3 Write property test for Landlock ABI negotiation
    - **Property 8: Policy Serialization Round-Trip**
    - **Validates: Requirements 12.1, 12.2**
    - Generate random Policy structures with varying paths and flags
    - Serialize to JSON, deserialize, verify equality
    - Run 100 iterations with proptest
    - _Requirements: 12.1, 12.2_

  - [ ]* 1.4 Write integration tests for Landlock V5 enforcement
    - Test unauthorized file reads are blocked
    - Test workspace directory is accessible
    - Test per-process temp directory is accessible
    - Test V5 features (ioctl restrictions) when available
    - _Requirements: 14.1, 14.2, 15.1_

- [x] 2. Implement seccomp filter builder with TSYNC flag
  - [x] 2.1 Add seccompiler crate dependency to Cargo.toml
    - Add seccompiler = "0.4" to dependencies
    - Add libc for syscall constants
    - _Requirements: 17.1, 17.3_

  - [x] 2.2 Define syscall categories in seccomp.rs
    - Create allowlist (~130 syscalls: file I/O, memory, process, signals, time, networking, threading)
    - Create denylist (io_uring syscalls, async I/O - return EPERM)
    - Create killlist (kernel manipulation, namespace creation, debugging - KILL_PROCESS)
    - Document rationale for each category
    - _Requirements: 1.3, 1.4, 1.5, 1.6, 1.7_

  - [x] 2.3 Implement conditional argument filtering for clone, socket, personality
    - Add ArgCondition struct with arg_index, operator, value fields
    - Implement clone filter to block CLONE_NEW* flags using MaskedEq
    - Implement socket filter to block AF_VSOCK (domain == 40)
    - Implement personality filter to allow only safe values (0, ADDR_NO_RANDOMIZE, PER_LINUX32)
    - Handle strict vs best-effort mode for clone3 syscall
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [x] 2.4 Implement BPF filter compilation and installation
    - Create apply_seccomp() function using seccompiler crate
    - Add architecture validation (x86_64 only)
    - Install filter with SECCOMP_FILTER_FLAG_TSYNC for multi-threaded runtimes
    - Add error handling and diagnostics logging
    - _Requirements: 1.1, 1.2, 3.2, 3.3, 3.4_

  - [x] 2.5 Implement set_no_new_privs() function
    - Use prctl(PR_SET_NO_NEW_PRIVS) before seccomp installation
    - Add error handling for prctl failures
    - _Requirements: 3.1_

  - [ ]* 2.6 Write property test for killlist syscall termination
    - **Property 1: Killlist Syscall Termination**
    - **Validates: Requirements 1.5**
    - Generate random killlist syscalls (kexec_load, init_module, etc.)
    - Fork child process, attempt syscall, verify process is killed
    - Run 100 iterations with proptest
    - _Requirements: 1.5, 15.2_

  - [ ]* 2.7 Write property test for denylist syscall EPERM
    - **Property 2: Denylist Syscall Returns EPERM**
    - **Validates: Requirements 1.6**
    - Generate random denylist syscalls (io_uring_setup, etc.)
    - Fork child process, attempt syscall, verify EPERM returned
    - Run 100 iterations with proptest
    - _Requirements: 1.6, 15.2_

  - [ ]* 2.8 Write property test for default deny behavior
    - **Property 3: Default Deny for Uncategorized Syscalls**
    - **Validates: Requirements 1.7**
    - Generate random syscall numbers not in any category
    - Fork child process, attempt syscall, verify EPERM returned
    - Run 100 iterations with proptest
    - _Requirements: 1.7, 15.2_

  - [ ]* 2.9 Write property test for clone namespace flag blocking
    - **Property 4: Clone with Namespace Flags Blocked**
    - **Validates: Requirements 2.1**
    - Generate random combinations of CLONE_NEW* flags
    - Fork child process, attempt clone with flags, verify EPERM
    - Run 100 iterations with proptest
    - _Requirements: 2.1, 15.2_

  - [ ]* 2.10 Write property test for AF_VSOCK socket blocking
    - **Property 5: AF_VSOCK Socket Creation Blocked**
    - **Validates: Requirements 2.2**
    - Generate random socket types/protocols with AF_VSOCK domain
    - Fork child process, attempt socket creation, verify EPERM
    - Run 100 iterations with proptest
    - _Requirements: 2.2, 15.2_

  - [ ]* 2.11 Write property test for personality syscall filtering
    - **Property 6: Personality Syscall Conditional Filtering**
    - **Validates: Requirements 2.3**
    - Generate random personality values (safe and unsafe)
    - Fork child process, attempt personality syscall, verify success/EPERM
    - Run 100 iterations with proptest
    - _Requirements: 2.3, 15.2_

  - [ ]* 2.12 Write property test for seccomp filter inheritance
    - **Property 7: Seccomp Filter Inheritance**
    - **Validates: Requirements 3.5**
    - Generate random allowlist/denylist syscalls
    - Fork child with seccomp, fork grandchild, verify filter active in grandchild
    - Run 100 iterations with proptest
    - _Requirements: 3.5, 15.2_

- [ ] 3. Checkpoint - Ensure seccomp tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Implement namespace manager with re-exec launcher
  - [ ] 4.1 Update launcher.rs with namespace probing
    - Implement probe_namespace_support() to test CLONE_NEWUSER availability
    - Add NamespaceSupport struct to track available namespaces
    - Log detected namespace capabilities at initialization
    - _Requirements: 4.1, 13.3_

  - [ ] 4.2 Implement namespace creation in launcher.rs
    - Create user namespace (CLONE_NEWUSER) for unprivileged operation
    - Create network namespace (CLONE_NEWNET) for network isolation
    - Create mount namespace (CLONE_NEWNS) for strict mode only
    - Set Pdeathsig to SIGTERM for child cleanup
    - Create new process group for descendant cleanup
    - _Requirements: 4.2, 4.3, 4.4, 4.5, 4.6_

  - [ ] 4.3 Implement UID/GID mapping in launcher.rs
    - Write /proc/self/uid_map to map current UID to UID 0 inside namespace
    - Write /proc/self/gid_map to map current GID to GID 0 inside namespace
    - Handle setgroups denial for unprivileged operation
    - _Requirements: 4.3_

  - [ ] 4.4 Implement best-effort mode fallback in launcher.rs
    - Fork child without namespace flags when namespaces unavailable
    - Set sentinel environment variable to indicate degraded mode
    - Log warning about advisory isolation
    - _Requirements: 4.7, 9.5, 16.4_

  - [ ]* 4.5 Write integration tests for namespace isolation
    - Test network namespace only has loopback interface
    - Test UID/GID mapping is correct inside user namespace
    - Test processes cannot escape namespace isolation
    - Test Pdeathsig kills child when parent dies
    - _Requirements: 4.2, 4.3, 4.5, 15.3_

- [ ] 5. Implement sandbox child initialization sequence
  - [ ] 5.1 Update child.rs with containment layer ordering
    - Apply layers in order: capabilities, loopback, mount /dev/shm, Landlock, resource limits, no_new_privs, seccomp
    - Report status of each layer to stderr
    - Implement strict mode fail-closed behavior
    - Implement best-effort mode warning behavior
    - _Requirements: 5.1, 5.3, 5.4, 5.5_

  - [ ] 5.2 Implement per-process temp directory creation in child.rs
    - Create /tmp/pipelock-sandbox-{PID} directory
    - Add temp directory to Policy read-write allowlist
    - Set TMPDIR environment variable
    - Ensure cleanup in launcher after child exits
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 5.2_

  - [ ] 5.3 Implement target command execution in child.rs
    - Execute target command via execve after all layers applied
    - Replace child process with target command
    - Preserve operator-specified extra environment variables
    - _Requirements: 5.6_

  - [ ]* 5.4 Write integration tests for initialization sequence
    - Test layers are applied in correct order
    - Test per-process temp directory is accessible
    - Test TMPDIR environment variable is set correctly
    - Test temp directory is removed after exit
    - _Requirements: 5.1, 5.2, 8.1, 8.2, 8.3, 8.4, 15.5_

- [ ] 6. Implement capability dropping
  - [ ] 6.1 Update caps.rs with comprehensive capability dropping
    - Drop bounding set capabilities (0-40) using PR_CAPBSET_DROP
    - Drop effective, permitted, inheritable sets using capset
    - Handle EINVAL (capability doesn't exist) gracefully
    - Handle EPERM (user namespace) gracefully
    - _Requirements: 6.1, 6.2, 6.3_

  - [ ] 6.2 Integrate capability dropping into child initialization
    - Call drop_all_capabilities() after namespace creation
    - Call before applying Landlock (Landlock needs CAP_SYS_ADMIN)
    - Add error handling for strict vs best-effort mode
    - _Requirements: 6.3, 6.4, 6.5_

  - [ ]* 6.3 Write integration tests for capability dropping
    - Test privileged operations fail after capability dropping
    - Test EPERM errors are handled gracefully in user namespaces
    - Test capabilities are dropped before Landlock is applied
    - _Requirements: 6.1, 6.2, 6.3, 15.4_

- [ ] 7. Implement network namespace loopback configuration
  - [ ] 7.1 Add rtnetlink dependency to Cargo.toml
    - Add rtnetlink crate for network interface management
    - Add tokio runtime for async operations
    - _Requirements: 10.2_

  - [ ] 7.2 Implement configure_loopback() in netns.rs
    - Use rtnetlink to bring up loopback interface
    - Add 127.0.0.1/8 address to loopback
    - Handle errors gracefully (non-fatal)
    - Skip configuration when no network namespace exists
    - _Requirements: 10.1, 10.2, 10.3, 10.4_

  - [ ] 7.3 Integrate loopback configuration into child initialization
    - Call configure_loopback() after namespace creation
    - Call before applying Landlock (needs /sys access)
    - Log network namespace status (ACTIVE or DEGRADED)
    - _Requirements: 10.5_

  - [ ]* 7.4 Write integration tests for loopback configuration
    - Test loopback interface is active in network namespace
    - Test localhost connections work
    - Test configuration is skipped in best-effort mode without namespace
    - _Requirements: 10.1, 10.3, 10.4, 15.3_

- [ ] 8. Checkpoint - Ensure namespace and capability tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Implement private /dev/shm mount for strict mode
  - [ ] 9.1 Implement mount_private_shm() in child.rs
    - Unmount host /dev/shm
    - Mount new tmpfs at /dev/shm with 64MB size limit
    - Only execute in strict mode with mount namespace
    - Exit with status 1 on failure in strict mode
    - _Requirements: 7.1, 7.2, 7.3_

  - [ ] 9.2 Integrate /dev/shm mount into child initialization
    - Call mount_private_shm() after namespace creation
    - Call before applying Landlock
    - Log whether /dev/shm is private or shared
    - Skip in best-effort mode
    - _Requirements: 7.4, 7.5_

  - [ ]* 9.3 Write integration tests for /dev/shm isolation
    - Test private /dev/shm is mounted in strict mode
    - Test shared memory segments are isolated
    - Test mount is skipped in best-effort mode
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [ ] 10. Implement policy validation and serialization
  - [ ] 10.1 Implement Policy::validate() in lib.rs
    - Check for secret directories (.ssh, .aws, .gnupg, .kube, .docker, .config/gcloud, .azure, .terraform.d)
    - Return InvalidPolicy error if secret directories are in allowlist
    - Validate workspace is absolute path
    - _Requirements: 12.4_

  - [ ] 10.2 Implement policy serialization in launcher.rs
    - Serialize Policy to JSON using serde_json
    - Pass via __PIPELOCK_SANDBOX_POLICY environment variable
    - Include workspace, strict, best_effort flags
    - _Requirements: 12.1_

  - [ ] 10.3 Implement policy deserialization in child.rs
    - Deserialize Policy from environment variable
    - Use default policy if none provided
    - Validate policy before applying Landlock
    - _Requirements: 12.2, 12.3, 12.4_

  - [ ]* 10.4 Write property test for secret directory validation
    - **Property 9: Secret Directory Validation Rejection**
    - **Validates: Requirements 12.4**
    - Generate random policies with paths including secret directories
    - Call validate(), verify InvalidPolicy error returned
    - Run 100 iterations with proptest
    - _Requirements: 12.4, 15.5_

  - [ ]* 10.5 Write integration tests for policy serialization
    - Test policy round-trip (serialize, deserialize, verify equality)
    - Test default policy is used when none provided
    - Test validation errors are reported clearly
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 15.5_

- [ ] 11. Implement environment variable sanitization
  - [ ] 11.1 Implement sanitize_environment() in child.rs
    - Construct synthetic environment with only: PATH, HOME, USER, TMPDIR, HTTP_PROXY, HTTPS_PROXY, NO_PROXY
    - Remove all __PIPELOCK_SANDBOX_* internal variables
    - Set TMPDIR to per-process temp directory
    - Preserve operator-specified extra environment variables
    - _Requirements: 11.1, 11.2, 11.3, 11.5_

  - [ ] 11.2 Integrate environment sanitization into child initialization
    - Call sanitize_environment() before executing target command
    - Log warning about advisory HTTP_PROXY in best-effort mode without namespace
    - _Requirements: 11.4_

  - [ ]* 11.3 Write integration tests for environment sanitization
    - Test only allowed variables are present
    - Test internal sandbox variables are removed
    - Test TMPDIR points to per-process temp directory
    - Test extra environment variables are preserved
    - _Requirements: 11.1, 11.2, 11.3, 11.5_

- [ ] 12. Implement strict vs best-effort mode selection
  - [ ] 12.1 Add mode flags to Policy struct in lib.rs
    - Add strict: bool field
    - Add best_effort: bool field
    - Validate both cannot be enabled simultaneously
    - _Requirements: 9.1, 9.2, 9.3_

  - [ ] 12.2 Implement strict mode fail-closed behavior
    - Exit with status 1 if Landlock, seccomp, or network namespace fail
    - Log fatal errors with layer name and remediation
    - Report "X/6 layers active (STRICT)" summary
    - _Requirements: 9.4, 16.1, 16.2, 16.3_

  - [ ] 12.3 Implement best-effort mode graceful degradation
    - Continue with warnings when layers fail
    - Log "X/6 layers active" summary with degraded layers
    - Log warning about advisory network isolation when namespace unavailable
    - _Requirements: 9.5, 16.1, 16.2, 16.3, 16.4_

  - [ ]* 12.4 Write integration tests for mode selection
    - Test strict mode fails when any layer is unavailable
    - Test best-effort mode continues with warnings when layers fail
    - Test both modes cannot be enabled simultaneously
    - Test clone3 is blocked in strict mode and allowed in best-effort mode
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 15.6, 15.7_

- [ ] 13. Checkpoint - Ensure policy and mode tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 14. Implement platform detection and error handling
  - [ ] 14.1 Implement platform detection in lib.rs
    - Return Unsupported error on non-Linux platforms
    - Return Unsupported error on non-x86_64 architectures
    - Probe for user namespace support
    - Detect Landlock ABI version
    - _Requirements: 13.1, 13.2, 13.3, 13.4_

  - [ ] 14.2 Implement structured error types in lib.rs
    - Define SandboxError enum with variants: Unsupported, InvalidPolicy, Landlock, Seccomp, Namespace, CapabilityDrop, NetworkConfig, Mount
    - Implement Display and Error traits
    - Use thiserror crate for error derivation
    - _Requirements: 16.5_

  - [ ] 14.3 Implement diagnostic logging throughout codebase
    - Log layer name, error reason, and remediation on failures
    - Distinguish fatal errors (strict) from warnings (best-effort)
    - Log platform capabilities at initialization
    - Report active layer summary before executing target command
    - _Requirements: 13.5, 16.1, 16.2, 16.3_

  - [ ]* 14.4 Write integration tests for platform detection
    - Test non-Linux platforms return Unsupported error (use conditional compilation)
    - Test non-x86_64 architectures return Unsupported error (use conditional compilation)
    - Test platform capabilities are logged at initialization
    - _Requirements: 13.1, 13.2, 13.5_

- [ ] 15. Add comprehensive documentation
  - [ ] 15.1 Write module-level documentation in lib.rs
    - Explain re-exec launcher pattern
    - Document containment layer ordering and rationale
    - Provide quick-start examples for strict and best-effort modes
    - _Requirements: 18.1, 18.3_

  - [ ] 15.2 Add doc comments to all public types
    - Document Policy struct with usage examples
    - Document SandboxError enum with error handling patterns
    - Document apply() function with examples
    - Document differences between strict and best-effort modes
    - _Requirements: 18.2, 18.4_

  - [ ] 15.3 Document syscall categories in seccomp.rs
    - Add code comments for allowlist with rationale
    - Add code comments for denylist with rationale
    - Add code comments for killlist with rationale
    - Explain conditional filtering for clone, socket, personality
    - _Requirements: 18.5_

  - [ ] 15.4 Update README.md in crate root
    - Add quick-start examples
    - Document strict vs best-effort modes
    - Add platform requirements (Linux, x86_64, kernel 5.13+)
    - Add troubleshooting section
    - _Requirements: 18.3_

- [ ] 16. Final integration and wiring
  - [ ] 16.1 Wire all components together in lib.rs
    - Export public API: Policy, SandboxError, apply()
    - Integrate launcher, child, seccomp, caps, netns modules
    - Ensure all layers are called in correct order
    - _Requirements: 14.3_

  - [ ] 16.2 Update Cargo.toml with all dependencies
    - Pin dependency versions for reproducible builds
    - Add feature flags for optional functionality
    - Document dependency rationale in comments
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5_

  - [ ] 16.3 Configure test execution for serial namespace tests
    - Add test configuration to Cargo.toml for serial execution
    - Add CI environment detection for skipping namespace tests
    - Document test execution requirements in README
    - _Requirements: 15.1, 15.6, 15.7_

  - [ ]* 16.4 Write end-to-end integration tests
    - Test complete sandbox initialization with all layers
    - Test Go, Python, Node.js runtimes work correctly
    - Test multi-threaded applications with TSYNC flag
    - Test cleanup and resource management
    - _Requirements: 15.1, 15.5, 15.6, 15.7_

- [ ] 17. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at reasonable breaks
- Property tests validate universal correctness properties (9 properties × 100 iterations)
- Integration tests validate specific scenarios and platform-dependent behavior (~30 tests)
- All tests must run serially due to namespace isolation: `cargo test -p agent-sandbox -- --test-threads=1`
- Tests requiring user namespaces should be skipped in CI environments where this feature is disabled
- The implementation uses Rust throughout (no pseudocode), leveraging type safety for compile-time correctness
