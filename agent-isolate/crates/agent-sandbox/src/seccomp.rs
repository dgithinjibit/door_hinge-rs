//! Seccomp BPF filter construction and installation.
//!
//! This module implements syscall filtering using seccomp-BPF. The filter
//! validates architecture (x86_64 only), applies conditional argument
//! filtering for dangerous syscalls (clone, socket, personality), and
//! enforces a curated allowlist of ~130 syscalls compatible with Go,
//! Python, and Node.js runtimes.

#![cfg(target_os = "linux")]

use crate::SandboxError;
use std::os::raw::c_ushort;

// seccomp_data offsets (struct seccomp_data layout from <linux/seccomp.h>)
const SECCOMP_DATA_NR_OFFSET: u32 = 0; // syscall number
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4; // architecture
const SECCOMP_DATA_ARGS_OFFSET: u32 = 16; // args[0] low 32 bits

// BPF instruction codes
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// Seccomp return values
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_ERRNO: u32 = 0x00050000;

// Architecture constant for x86_64
const AUDIT_ARCH_X86_64: u32 = 0xc000003e;

// Clone flags that create new namespaces
const CLONE_NEW_MASK: u32 = 0x7E020000; // NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET

// AF_VSOCK socket family (VM host-guest communication)
const AF_VSOCK: u32 = 40;

// Personality syscall constants
const PERSONALITY_QUERY: u32 = 0xFFFFFFFF;
const ADDR_NO_RANDOMIZE: u32 = 0x00000008;
const PER_LINUX32: u32 = 0x00020000;
const PER_LINUX32_NO_RANDOMIZE: u32 = 0x00020008;

/// BPF instruction (sock_filter from <linux/filter.h>)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockFilter {
    code: c_ushort,
    jt: u8,
    jf: u8,
    k: u32,
}

/// BPF program (sock_fprog from <linux/filter.h>)
#[repr(C)]
struct SockFprog {
    len: c_ushort,
    filter: *const SockFilter,
}

/// Apply seccomp BPF filter to the current process.
///
/// MUST be called after `set_no_new_privs()`. The filter is permanent and
/// inherited by all children (fork + exec).
///
/// In strict mode, clone3 is blocked entirely (EPERM) since BPF cannot
/// inspect its pointer argument for CLONE_NEW* flags.
pub(crate) fn apply_seccomp(strict: bool) -> Result<(), SandboxError> {
    let filter = build_seccomp_filter(strict);

    let prog = SockFprog {
        len: filter.len() as c_ushort,
        filter: filter.as_ptr(),
    };

    // Install the BPF filter using seccomp(2) syscall
    // SECCOMP_SET_MODE_FILTER = 1, SECCOMP_FILTER_FLAG_TSYNC = 1
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1, // SECCOMP_SET_MODE_FILTER
            1, // SECCOMP_FILTER_FLAG_TSYNC (sync across all threads)
            &prog as *const SockFprog,
        )
    };

    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(SandboxError::Seccomp(format!(
            "seccomp install failed: {}",
            errno
        )));
    }

    tracing::info!(
        target: "agent.sandbox",
        "Seccomp filter installed ({} instructions)",
        filter.len()
    );

    Ok(())
}

/// Set PR_SET_NO_NEW_PRIVS flag.
///
/// Required before installing a seccomp filter without CAP_SYS_ADMIN.
/// This is permanent and prevents privilege escalation via suid/sgid binaries.
pub(crate) fn set_no_new_privs() -> Result<(), SandboxError> {
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(SandboxError::Seccomp(format!(
            "PR_SET_NO_NEW_PRIVS failed: {}",
            errno
        )));
    }
    Ok(())
}

/// Build the seccomp BPF filter program.
fn build_seccomp_filter(strict: bool) -> Vec<SockFilter> {
    let allow = allowed_syscalls();
    let kill = kill_syscalls();
    let deny = deny_syscalls();

    let mut prog = Vec::new();

    // Step 1: Validate architecture is x86_64
    prog.push(bpf_load(SECCOMP_DATA_ARCH_OFFSET));
    prog.push(bpf_jump_eq(AUDIT_ARCH_X86_64, 1, 0));
    prog.push(bpf_ret(SECCOMP_RET_KILL_PROCESS)); // wrong arch = kill

    // Step 2: Load syscall number
    prog.push(bpf_load(SECCOMP_DATA_NR_OFFSET));

    // Step 3: Kill-on-match for critical syscalls
    for &nr in &kill {
        prog.push(bpf_jump_eq(nr, 0, 1));
        prog.push(bpf_ret(SECCOMP_RET_KILL_PROCESS));
    }

    // Step 3b: Deny-on-match (EPERM, not KILL)
    for &nr in &deny {
        prog.push(bpf_jump_eq(nr, 0, 1));
        prog.push(bpf_ret(SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }

    // Step 4: Conditional argument filtering
    prog.extend(clone_conditional());
    prog.extend(clone3_conditional(strict));
    prog.extend(socket_conditional());
    prog.extend(personality_conditional());

    // Reload syscall number after conditional blocks
    prog.push(bpf_load(SECCOMP_DATA_NR_OFFSET));

    // Step 5: Allow-on-match for safe syscalls
    let conditional_set = [
        libc::SYS_clone as u32,
        libc::SYS_clone3 as u32,
        libc::SYS_socket as u32,
        libc::SYS_personality as u32,
    ];

    for &nr in &allow {
        if kill.contains(&nr) || deny.contains(&nr) || conditional_set.contains(&nr) {
            continue; // already handled
        }
        prog.push(bpf_jump_eq(nr, 0, 1));
        prog.push(bpf_ret(SECCOMP_RET_ALLOW));
    }

    // Step 6: Default deny
    prog.push(bpf_ret(SECCOMP_RET_ERRNO | libc::EPERM as u32));

    prog
}

// BPF instruction helpers

fn bpf_load(offset: u32) -> SockFilter {
    SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: offset,
    }
}

fn bpf_jump_eq(val: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt,
        jf,
        k: val,
    }
}

fn bpf_jump_set(val: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code: BPF_JMP | BPF_JSET | BPF_K,
        jt,
        jf,
        k: val,
    }
}

fn bpf_ret(val: u32) -> SockFilter {
    SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: val,
    }
}

// Conditional filtering blocks

fn clone_conditional() -> Vec<SockFilter> {
    vec![
        bpf_jump_eq(libc::SYS_clone as u32, 0, 4),
        bpf_load(SECCOMP_DATA_ARGS_OFFSET),
        bpf_jump_set(CLONE_NEW_MASK, 0, 1),
        bpf_ret(SECCOMP_RET_ERRNO | libc::EPERM as u32),
        bpf_ret(SECCOMP_RET_ALLOW),
    ]
}

fn clone3_conditional(strict: bool) -> Vec<SockFilter> {
    if strict {
        vec![
            bpf_jump_eq(libc::SYS_clone3 as u32, 0, 1),
            bpf_ret(SECCOMP_RET_ERRNO | libc::EPERM as u32),
        ]
    } else {
        vec![
            bpf_jump_eq(libc::SYS_clone3 as u32, 0, 1),
            bpf_ret(SECCOMP_RET_ALLOW),
        ]
    }
}

fn socket_conditional() -> Vec<SockFilter> {
    vec![
        bpf_jump_eq(libc::SYS_socket as u32, 0, 4),
        bpf_load(SECCOMP_DATA_ARGS_OFFSET),
        bpf_jump_eq(AF_VSOCK, 0, 1),
        bpf_ret(SECCOMP_RET_ERRNO | libc::EPERM as u32),
        bpf_ret(SECCOMP_RET_ALLOW),
    ]
}

fn personality_conditional() -> Vec<SockFilter> {
    vec![
        bpf_jump_eq(libc::SYS_personality as u32, 0, 8),
        bpf_load(SECCOMP_DATA_ARGS_OFFSET),
        bpf_jump_eq(0, 5, 0), // PER_LINUX
        bpf_jump_eq(ADDR_NO_RANDOMIZE, 4, 0),
        bpf_jump_eq(PER_LINUX32, 3, 0),
        bpf_jump_eq(PER_LINUX32_NO_RANDOMIZE, 2, 0),
        bpf_jump_eq(PERSONALITY_QUERY, 1, 0),
        bpf_ret(SECCOMP_RET_ERRNO | libc::EPERM as u32),
        bpf_ret(SECCOMP_RET_ALLOW),
    ]
}

// Syscall lists

fn allowed_syscalls() -> Vec<u32> {
    vec![
        // Memory management
        libc::SYS_brk as u32,
        libc::SYS_mmap as u32,
        libc::SYS_munmap as u32,
        libc::SYS_mremap as u32,
        libc::SYS_mprotect as u32,
        libc::SYS_madvise as u32,
        libc::SYS_mincore as u32,
        libc::SYS_mlock as u32,
        libc::SYS_mlock2 as u32,
        libc::SYS_munlock as u32,
        libc::SYS_mlockall as u32,
        libc::SYS_munlockall as u32,
        libc::SYS_msync as u32,
        libc::SYS_memfd_create as u32,
        libc::SYS_membarrier as u32,
        libc::SYS_pkey_alloc as u32,
        libc::SYS_pkey_free as u32,
        libc::SYS_pkey_mprotect as u32,
        // File I/O
        libc::SYS_read as u32,
        libc::SYS_write as u32,
        libc::SYS_openat as u32,
        libc::SYS_close as u32,
        libc::SYS_lseek as u32,
        libc::SYS_pread64 as u32,
        libc::SYS_pwrite64 as u32,
        libc::SYS_readv as u32,
        libc::SYS_writev as u32,
        libc::SYS_preadv as u32,
        libc::SYS_pwritev as u32,
        libc::SYS_preadv2 as u32,
        libc::SYS_pwritev2 as u32,
        libc::SYS_fstat as u32,
        libc::SYS_newfstatat as u32,
        libc::SYS_statx as u32,
        libc::SYS_fstatfs as u32,
        libc::SYS_statfs as u32,
        libc::SYS_readlink as u32,
        libc::SYS_readlinkat as u32,
        libc::SYS_faccessat as u32,
        libc::SYS_faccessat2 as u32,
        libc::SYS_ftruncate as u32,
        libc::SYS_truncate as u32,
        libc::SYS_fallocate as u32,
        libc::SYS_fadvise64 as u32,
        libc::SYS_fcntl as u32,
        libc::SYS_flock as u32,
        libc::SYS_ioctl as u32,
        libc::SYS_dup as u32,
        libc::SYS_dup2 as u32,
        libc::SYS_dup3 as u32,
        libc::SYS_getdents64 as u32,
        libc::SYS_copy_file_range as u32,
        libc::SYS_splice as u32,
        libc::SYS_tee as u32,
        libc::SYS_sendfile as u32,
        libc::SYS_readahead as u32,
        libc::SYS_fchmod as u32,
        libc::SYS_fchmodat as u32,
        libc::SYS_fchown as u32,
        libc::SYS_fchownat as u32,
        libc::SYS_mkdirat as u32,
        libc::SYS_unlinkat as u32,
        libc::SYS_renameat as u32,
        libc::SYS_renameat2 as u32,
        libc::SYS_symlinkat as u32,
        libc::SYS_linkat as u32,
        libc::SYS_umask as u32,
        libc::SYS_getcwd as u32,
        libc::SYS_chdir as u32,
        libc::SYS_fchdir as u32,
        // Network
        libc::SYS_socketpair as u32,
        libc::SYS_bind as u32,
        libc::SYS_listen as u32,
        libc::SYS_accept as u32,
        libc::SYS_accept4 as u32,
        libc::SYS_connect as u32,
        libc::SYS_getsockname as u32,
        libc::SYS_getpeername as u32,
        libc::SYS_getsockopt as u32,
        libc::SYS_setsockopt as u32,
        libc::SYS_shutdown as u32,
        libc::SYS_sendto as u32,
        libc::SYS_recvfrom as u32,
        libc::SYS_sendmsg as u32,
        libc::SYS_recvmsg as u32,
        libc::SYS_sendmmsg as u32,
        libc::SYS_recvmmsg as u32,
        // Epoll / event loop
        libc::SYS_epoll_create1 as u32,
        libc::SYS_epoll_ctl as u32,
        libc::SYS_epoll_wait as u32,
        libc::SYS_epoll_pwait as u32,
        libc::SYS_epoll_pwait2 as u32,
        libc::SYS_eventfd as u32,
        libc::SYS_eventfd2 as u32,
        libc::SYS_timerfd_create as u32,
        libc::SYS_timerfd_settime as u32,
        libc::SYS_timerfd_gettime as u32,
        libc::SYS_signalfd4 as u32,
        libc::SYS_inotify_init1 as u32,
        libc::SYS_inotify_add_watch as u32,
        libc::SYS_inotify_rm_watch as u32,
        libc::SYS_poll as u32,
        libc::SYS_ppoll as u32,
        libc::SYS_pselect6 as u32,
        libc::SYS_select as u32,
        // Process management
        libc::SYS_fork as u32,
        libc::SYS_vfork as u32,
        libc::SYS_execve as u32,
        libc::SYS_execveat as u32,
        libc::SYS_wait4 as u32,
        libc::SYS_waitid as u32,
        libc::SYS_exit as u32,
        libc::SYS_exit_group as u32,
        libc::SYS_kill as u32,
        libc::SYS_tgkill as u32,
        libc::SYS_tkill as u32,
        libc::SYS_getpid as u32,
        libc::SYS_getppid as u32,
        libc::SYS_gettid as u32,
        libc::SYS_getpgrp as u32,
        libc::SYS_getpgid as u32,
        libc::SYS_setpgid as u32,
        libc::SYS_setsid as u32,
        libc::SYS_prctl as u32,
        libc::SYS_prlimit64 as u32,
        libc::SYS_getrlimit as u32,
        libc::SYS_setrlimit as u32,
        libc::SYS_getrusage as u32,
        libc::SYS_sched_yield as u32,
        libc::SYS_sched_getaffinity as u32,
        libc::SYS_sched_setaffinity as u32,
        libc::SYS_sched_getscheduler as u32,
        libc::SYS_sched_setscheduler as u32,
        libc::SYS_sched_getparam as u32,
        libc::SYS_sched_setparam as u32,
        libc::SYS_sched_get_priority_max as u32,
        libc::SYS_sched_get_priority_min as u32,
        // Signals
        libc::SYS_rt_sigaction as u32,
        libc::SYS_rt_sigprocmask as u32,
        libc::SYS_rt_sigreturn as u32,
        libc::SYS_rt_sigpending as u32,
        libc::SYS_rt_sigsuspend as u32,
        libc::SYS_rt_sigtimedwait as u32,
        libc::SYS_rt_sigqueueinfo as u32,
        libc::SYS_rt_tgsigqueueinfo as u32,
        libc::SYS_sigaltstack as u32,
        // Timers / clock
        libc::SYS_clock_gettime as u32,
        libc::SYS_clock_getres as u32,
        libc::SYS_clock_nanosleep as u32,
        libc::SYS_nanosleep as u32,
        libc::SYS_setitimer as u32,
        libc::SYS_getitimer as u32,
        libc::SYS_timer_create as u32,
        libc::SYS_timer_settime as u32,
        libc::SYS_timer_gettime as u32,
        libc::SYS_timer_getoverrun as u32,
        libc::SYS_timer_delete as u32,
        libc::SYS_gettimeofday as u32,
        libc::SYS_times as u32,
        libc::SYS_alarm as u32,
        // Thread setup
        libc::SYS_arch_prctl as u32,
        libc::SYS_set_tid_address as u32,
        libc::SYS_set_robust_list as u32,
        libc::SYS_get_robust_list as u32,
        libc::SYS_futex as u32,
        libc::SYS_rseq as u32,
        libc::SYS_pipe as u32,
        libc::SYS_pipe2 as u32,
        // Identity / credentials
        libc::SYS_getuid as u32,
        libc::SYS_getgid as u32,
        libc::SYS_geteuid as u32,
        libc::SYS_getegid as u32,
        libc::SYS_getgroups as u32,
        libc::SYS_getresuid as u32,
        libc::SYS_getresgid as u32,
        libc::SYS_setuid as u32,
        libc::SYS_setgid as u32,
        libc::SYS_setreuid as u32,
        libc::SYS_setregid as u32,
        libc::SYS_setresuid as u32,
        libc::SYS_setresgid as u32,
        libc::SYS_setfsuid as u32,
        libc::SYS_setfsgid as u32,
        libc::SYS_setgroups as u32,
        libc::SYS_capget as u32,
        libc::SYS_capset as u32,
        // IPC
        libc::SYS_shmget as u32,
        libc::SYS_shmat as u32,
        libc::SYS_shmdt as u32,
        libc::SYS_shmctl as u32,
        libc::SYS_semget as u32,
        libc::SYS_semop as u32,
        libc::SYS_semctl as u32,
        libc::SYS_semtimedop as u32,
        libc::SYS_msgget as u32,
        libc::SYS_msgsnd as u32,
        libc::SYS_msgrcv as u32,
        libc::SYS_msgctl as u32,
        libc::SYS_mq_open as u32,
        libc::SYS_mq_unlink as u32,
        libc::SYS_mq_timedsend as u32,
        libc::SYS_mq_timedreceive as u32,
        libc::SYS_mq_notify as u32,
        libc::SYS_mq_getsetattr as u32,
        // Misc
        libc::SYS_getrandom as u32,
        libc::SYS_uname as u32,
        libc::SYS_sysinfo as u32,
        libc::SYS_getcpu as u32,
        libc::SYS_seccomp as u32, // allow nested seccomp
    ]
}

fn kill_syscalls() -> Vec<u32> {
    vec![
        libc::SYS_kexec_load as u32,
        libc::SYS_kexec_file_load as u32,
        libc::SYS_init_module as u32,
        libc::SYS_finit_module as u32,
        libc::SYS_delete_module as u32,
        libc::SYS_reboot as u32,
    ]
}

fn deny_syscalls() -> Vec<u32> {
    vec![
        libc::SYS_io_uring_setup as u32,
        libc::SYS_io_uring_enter as u32,
        libc::SYS_io_uring_register as u32,
    ]
}
