use anyhow::{Result, anyhow, Context};
use std::path::Path;
use tracing::{info, warn, error};

#[cfg(all(feature = "linux", target_os = "linux"))]
use seccompiler::{
    BpfProgram, SeccompAction, SeccompFilter, SeccompRule, SeccompCmpArgLen, SeccompCmpOp,
    export_bpf,
};
#[cfg(all(feature = "linux", target_os = "linux"))]
use libseccomp::ScmpFilterContext;

/// Seccomp security profile types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityProfile {
    /// Basic profile that allows most operations but blocks dangerous syscalls
    Basic,
    /// Moderate profile restricts filesystem and network operations
    Moderate,
    /// Strict profile only allows minimal syscalls needed for basic program execution
    Strict,
    /// Custom profile with specified allow list
    Custom,
}

impl Default for SecurityProfile {
    fn default() -> Self {
        SecurityProfile::Moderate
    }
}

/// Create and apply a seccomp filter to the current process
#[cfg(all(feature = "linux", target_os = "linux"))]
pub fn apply_seccomp_filter(profile: SecurityProfile) -> Result<()> {
    info!("Applying seccomp filter with profile: {:?}", profile);
    
    // Create seccomp filter context
    let mut filter_ctx = ScmpFilterContext::new_filter(ScmpAction::KillProcess)
        .map_err(|e| anyhow!("Failed to create seccomp filter: {}", e))?;
    
    // Configure filter based on chosen security profile
    match profile {
        SecurityProfile::Basic => configure_basic_profile(&mut filter_ctx)?,
        SecurityProfile::Moderate => configure_moderate_profile(&mut filter_ctx)?,
        SecurityProfile::Strict => configure_strict_profile(&mut filter_ctx)?,
        SecurityProfile::Custom => {
            // Custom profile is now implemented
            configure_custom_profile(&mut filter_ctx)?;
        }
    }
    
    // Load the filter into the kernel
    filter_ctx.load()
        .map_err(|e| anyhow!("Failed to load seccomp filter: {}", e))?;
    
    info!("Successfully applied seccomp filter");
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn configure_basic_profile(filter: &mut ScmpFilterContext) -> Result<()> {
    // Allow common, safe syscalls needed for most programs
    let basic_allowed = [
        // Process/thread operations
        "exit", "exit_group", "futex", "get_robust_list", "nanosleep", "clock_nanosleep",
        "sched_yield", "sigaltstack", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", 
        
        // Memory management
        "brk", "mmap", "mprotect", "munmap", "mremap", "madvise",
        
        // File operations (read-only)
        "open", "openat", "read", "readv", "pread64", "readlink", "readlinkat", "close",
        "fstat", "stat", "lstat", "newfstatat", "access", "faccessat", "getdents", "getdents64",
        
        // Basic I/O
        "write", "writev", "pwrite64", "fsync", "fdatasync",
        
        // Process information
        "getpid", "gettid", "getppid", "getuid", "geteuid", "getgid", "getegid",
        
        // Time operations
        "clock_gettime", "gettimeofday", "time",
        
        // System information
        "uname", "sysinfo", "getrandom", "getcpu",
    ];
    
    // Add allowed syscalls
    for syscall in basic_allowed.iter() {
        add_allow_syscall(filter, syscall)?;
    }
    
    info!("Configured basic seccomp profile with {} allowed syscalls", basic_allowed.len());
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn configure_moderate_profile(filter: &mut ScmpFilterContext) -> Result<()> {
    // Moderate profile first includes all basic syscalls
    configure_basic_profile(filter)?;
    
    // Block or restrict further filesystem/network operations
    let moderate_denied = [
        // Network-related
        "socket", "socketpair", "bind", "connect", "listen", "accept", "accept4",
        "getsockname", "getpeername", "setsockopt", "getsockopt", "sendto", "recvfrom",
        "sendmsg", "recvmsg", "shutdown",
        
        // Filesystem modification
        "mkdir", "rmdir", "rename", "link", "symlink", "unlink", "chmod", "chown",
        "truncate", "ftruncate",
        
        // Process creation/control
        "clone", "fork", "vfork", "execve", "execveat", "kill", "tkill", "tgkill",
        
        // Privilege escalation
        "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid",
        "setgroups", "capset", "prctl",
        
        // System configuration
        "mount", "umount", "umount2", "pivot_root", "chroot", "swapon", "swapoff",
        "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module",
        "init_module", "delete_module", "kexec_load",
    ];
    
    // Deny dangerous syscalls
    for syscall in moderate_denied.iter() {
        add_deny_syscall(filter, syscall)?;
    }
    
    info!("Configured moderate seccomp profile with {} denied syscalls", moderate_denied.len());
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn configure_strict_profile(filter: &mut ScmpFilterContext) -> Result<()> {
    // Strict profile specifically allows only the minimal required syscalls
    let strict_allowed = [
        // Absolutely essential syscalls
        "exit", "exit_group", "brk", "mmap", "munmap", "mprotect",
        "read", "write", "close", "fstat", "clock_gettime",
    ];
    
    // Add only these syscalls to the allow list
    for syscall in strict_allowed.iter() {
        add_allow_syscall(filter, syscall)?;
    }
    
    info!("Configured strict seccomp profile with only {} allowed syscalls", strict_allowed.len());
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn add_allow_syscall(filter: &mut ScmpFilterContext, syscall_name: &str) -> Result<()> {
    let syscall_num = libseccomp::ScmpSyscall::from_name(syscall_name)
        .map_err(|_| anyhow!("Unknown syscall name: {}", syscall_name))?;
    
    filter.add_rule(libseccomp::ScmpAction::Allow, syscall_num)
        .map_err(|e| anyhow!("Failed to add rule to allow {}: {}", syscall_name, e))?;
    
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn add_deny_syscall(filter: &mut ScmpFilterContext, syscall_name: &str) -> Result<()> {
    let syscall_num = libseccomp::ScmpSyscall::from_name(syscall_name)
        .map_err(|_| anyhow!("Unknown syscall name: {}", syscall_name))?;
    
    filter.add_rule(libseccomp::ScmpAction::KillProcess, syscall_num)
        .map_err(|e| anyhow!("Failed to add rule to deny {}: {}", syscall_name, e))?;
    
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn configure_custom_profile(filter: &mut ScmpFilterContext) -> Result<()> {
    // Get configured syscalls from environment or configuration
    let allowed_syscalls = get_custom_syscall_allowlist()?;
    
    // Set default action to kill process
    filter.set_default_action(ScmpAction::KillProcess)
        .map_err(|e| anyhow!("Failed to set default action: {}", e))?;
    
    // Add allowed syscalls
    for syscall in &allowed_syscalls {
        add_allow_syscall(filter, syscall)?;
    }
    
    info!("Configured custom seccomp profile with {} allowed syscalls", allowed_syscalls.len());
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn get_custom_syscall_allowlist() -> Result<Vec<&'static str>> {
    // Try to get syscall allowlist from environment variable
    if let Ok(syscalls_env) = std::env::var("RUSTY_SANDBOX_ALLOWED_SYSCALLS") {
        let syscalls: Vec<&str> = syscalls_env.split(',')
            .map(|s| s.trim())
            .collect();
            
        // Convert to static strings (this is a bit of a hack but works for this purpose)
        let syscalls_static: Vec<&'static str> = syscalls.iter()
            .map(|&s| match s {
                "read" => "read",
                "write" => "write",
                "open" => "open",
                "close" => "close",
                "stat" => "stat",
                "fstat" => "fstat",
                "lstat" => "lstat",
                "poll" => "poll",
                "lseek" => "lseek",
                "mmap" => "mmap",
                "mprotect" => "mprotect",
                "munmap" => "munmap",
                "brk" => "brk",
                "rt_sigaction" => "rt_sigaction",
                "rt_sigprocmask" => "rt_sigprocmask",
                "rt_sigreturn" => "rt_sigreturn",
                "ioctl" => "ioctl",
                "pread64" => "pread64",
                "pwrite64" => "pwrite64",
                "readv" => "readv",
                "writev" => "writev",
                "access" => "access",
                "pipe" => "pipe",
                "select" => "select",
                "sched_yield" => "sched_yield",
                "mremap" => "mremap",
                "msync" => "msync",
                "mincore" => "mincore",
                "madvise" => "madvise",
                "shmget" => "shmget",
                "shmat" => "shmat",
                "shmctl" => "shmctl",
                "dup" => "dup",
                "dup2" => "dup2",
                "pause" => "pause",
                "nanosleep" => "nanosleep",
                "getitimer" => "getitimer",
                "alarm" => "alarm",
                "setitimer" => "setitimer",
                "getpid" => "getpid",
                "sendfile" => "sendfile",
                "socket" => "socket",
                "connect" => "connect",
                "accept" => "accept",
                "sendto" => "sendto",
                "recvfrom" => "recvfrom",
                "sendmsg" => "sendmsg",
                "recvmsg" => "recvmsg",
                "shutdown" => "shutdown",
                "bind" => "bind",
                "listen" => "listen",
                "getsockname" => "getsockname",
                "getpeername" => "getpeername",
                "socketpair" => "socketpair",
                "setsockopt" => "setsockopt",
                "getsockopt" => "getsockopt",
                "clone" => "clone",
                "fork" => "fork",
                "vfork" => "vfork",
                "execve" => "execve",
                "exit" => "exit",
                "wait4" => "wait4",
                "kill" => "kill",
                "uname" => "uname",
                "semget" => "semget",
                "semop" => "semop",
                "semctl" => "semctl",
                "shmdt" => "shmdt",
                "msgget" => "msgget",
                "msgsnd" => "msgsnd",
                "msgrcv" => "msgrcv",
                "msgctl" => "msgctl",
                "fcntl" => "fcntl",
                "flock" => "flock",
                "fsync" => "fsync",
                "fdatasync" => "fdatasync",
                "truncate" => "truncate",
                "ftruncate" => "ftruncate",
                "getdents" => "getdents",
                "getcwd" => "getcwd",
                "chdir" => "chdir",
                "fchdir" => "fchdir",
                "rename" => "rename",
                "mkdir" => "mkdir",
                "rmdir" => "rmdir",
                "creat" => "creat",
                "link" => "link",
                "unlink" => "unlink",
                "symlink" => "symlink",
                "readlink" => "readlink",
                "chmod" => "chmod",
                "fchmod" => "fchmod",
                "chown" => "chown",
                "fchown" => "fchown",
                "lchown" => "lchown",
                "umask" => "umask",
                "gettimeofday" => "gettimeofday",
                "getrlimit" => "getrlimit",
                "getrusage" => "getrusage",
                "sysinfo" => "sysinfo",
                "times" => "times",
                "ptrace" => "ptrace",
                "getuid" => "getuid",
                "syslog" => "syslog",
                "getgid" => "getgid",
                "setuid" => "setuid",
                "setgid" => "setgid",
                "geteuid" => "geteuid",
                "getegid" => "getegid",
                "setpgid" => "setpgid",
                "getppid" => "getppid",
                "getpgrp" => "getpgrp",
                "setsid" => "setsid",
                "setreuid" => "setreuid",
                "setregid" => "setregid",
                "getgroups" => "getgroups",
                "setgroups" => "setgroups",
                "setresuid" => "setresuid",
                "getresuid" => "getresuid",
                "setresgid" => "setresgid",
                "getresgid" => "getresgid",
                "getpgid" => "getpgid",
                "setfsuid" => "setfsuid",
                "setfsgid" => "setfsgid",
                "getsid" => "getsid",
                "capget" => "capget",
                "capset" => "capset",
                "rt_sigpending" => "rt_sigpending",
                "rt_sigtimedwait" => "rt_sigtimedwait",
                "rt_sigqueueinfo" => "rt_sigqueueinfo",
                "rt_sigsuspend" => "rt_sigsuspend",
                "sigaltstack" => "sigaltstack",
                "utime" => "utime",
                "mknod" => "mknod",
                "uselib" => "uselib",
                "personality" => "personality",
                "ustat" => "ustat",
                "statfs" => "statfs",
                "fstatfs" => "fstatfs",
                "sysfs" => "sysfs",
                "getpriority" => "getpriority",
                "setpriority" => "setpriority",
                "sched_setparam" => "sched_setparam",
                "sched_getparam" => "sched_getparam",
                "sched_setscheduler" => "sched_setscheduler",
                "sched_getscheduler" => "sched_getscheduler",
                "sched_get_priority_max" => "sched_get_priority_max",
                "sched_get_priority_min" => "sched_get_priority_min",
                "sched_rr_get_interval" => "sched_rr_get_interval",
                "mlock" => "mlock",
                "munlock" => "munlock",
                "mlockall" => "mlockall",
                "munlockall" => "munlockall",
                "vhangup" => "vhangup",
                "modify_ldt" => "modify_ldt",
                "pivot_root" => "pivot_root",
                "_sysctl" => "_sysctl",
                "prctl" => "prctl",
                "arch_prctl" => "arch_prctl",
                "adjtimex" => "adjtimex",
                "setrlimit" => "setrlimit",
                "chroot" => "chroot",
                "sync" => "sync",
                "acct" => "acct",
                "settimeofday" => "settimeofday",
                "mount" => "mount",
                "umount2" => "umount2",
                "swapon" => "swapon",
                "swapoff" => "swapoff",
                "reboot" => "reboot",
                "sethostname" => "sethostname",
                "setdomainname" => "setdomainname",
                "iopl" => "iopl",
                "ioperm" => "ioperm",
                "create_module" => "create_module",
                "init_module" => "init_module",
                "delete_module" => "delete_module",
                "get_kernel_syms" => "get_kernel_syms",
                "query_module" => "query_module",
                "quotactl" => "quotactl",
                "nfsservctl" => "nfsservctl",
                "getpmsg" => "getpmsg",
                "putpmsg" => "putpmsg",
                "afs_syscall" => "afs_syscall",
                "tuxcall" => "tuxcall",
                "security" => "security",
                "gettid" => "gettid",
                "readahead" => "readahead",
                "setxattr" => "setxattr",
                "lsetxattr" => "lsetxattr",
                "fsetxattr" => "fsetxattr",
                "getxattr" => "getxattr",
                "lgetxattr" => "lgetxattr",
                "fgetxattr" => "fgetxattr",
                "listxattr" => "listxattr",
                "llistxattr" => "llistxattr",
                "flistxattr" => "flistxattr",
                "removexattr" => "removexattr",
                "lremovexattr" => "lremovexattr",
                "fremovexattr" => "fremovexattr",
                "tkill" => "tkill",
                "time" => "time",
                "futex" => "futex",
                "sched_setaffinity" => "sched_setaffinity",
                "sched_getaffinity" => "sched_getaffinity",
                "set_thread_area" => "set_thread_area",
                "io_setup" => "io_setup",
                "io_destroy" => "io_destroy",
                "io_getevents" => "io_getevents",
                "io_submit" => "io_submit",
                "io_cancel" => "io_cancel",
                "get_thread_area" => "get_thread_area",
                "lookup_dcookie" => "lookup_dcookie",
                "epoll_create" => "epoll_create",
                "epoll_ctl_old" => "epoll_ctl_old",
                "epoll_wait_old" => "epoll_wait_old",
                "remap_file_pages" => "remap_file_pages",
                "getdents64" => "getdents64",
                "set_tid_address" => "set_tid_address",
                "restart_syscall" => "restart_syscall",
                "semtimedop" => "semtimedop",
                "fadvise64" => "fadvise64",
                "timer_create" => "timer_create",
                "timer_settime" => "timer_settime",
                "timer_gettime" => "timer_gettime",
                "timer_getoverrun" => "timer_getoverrun",
                "timer_delete" => "timer_delete",
                "clock_settime" => "clock_settime",
                "clock_gettime" => "clock_gettime",
                "clock_getres" => "clock_getres",
                "clock_nanosleep" => "clock_nanosleep",
                "exit_group" => "exit_group",
                "epoll_wait" => "epoll_wait",
                "epoll_ctl" => "epoll_ctl",
                "tgkill" => "tgkill",
                "utimes" => "utimes",
                "vserver" => "vserver",
                "mbind" => "mbind",
                "set_mempolicy" => "set_mempolicy",
                "get_mempolicy" => "get_mempolicy",
                "mq_open" => "mq_open",
                "mq_unlink" => "mq_unlink",
                "mq_timedsend" => "mq_timedsend",
                "mq_timedreceive" => "mq_timedreceive",
                "mq_notify" => "mq_notify",
                "mq_getsetattr" => "mq_getsetattr",
                "kexec_load" => "kexec_load",
                "waitid" => "waitid",
                "add_key" => "add_key",
                "request_key" => "request_key",
                "keyctl" => "keyctl",
                "ioprio_set" => "ioprio_set",
                "ioprio_get" => "ioprio_get",
                "inotify_init" => "inotify_init",
                "inotify_add_watch" => "inotify_add_watch",
                "inotify_rm_watch" => "inotify_rm_watch",
                "migrate_pages" => "migrate_pages",
                "openat" => "openat",
                "mkdirat" => "mkdirat",
                "mknodat" => "mknodat",
                "fchownat" => "fchownat",
                "futimesat" => "futimesat",
                "newfstatat" => "newfstatat",
                "unlinkat" => "unlinkat",
                "renameat" => "renameat",
                "linkat" => "linkat",
                "symlinkat" => "symlinkat",
                "readlinkat" => "readlinkat",
                "fchmodat" => "fchmodat",
                "faccessat" => "faccessat",
                "pselect6" => "pselect6",
                "ppoll" => "ppoll",
                "unshare" => "unshare",
                "set_robust_list" => "set_robust_list",
                "get_robust_list" => "get_robust_list",
                "splice" => "splice",
                "tee" => "tee",
                "sync_file_range" => "sync_file_range",
                "vmsplice" => "vmsplice",
                "move_pages" => "move_pages",
                "utimensat" => "utimensat",
                "epoll_pwait" => "epoll_pwait",
                "signalfd" => "signalfd",
                "timerfd_create" => "timerfd_create",
                "eventfd" => "eventfd",
                "fallocate" => "fallocate",
                "timerfd_settime" => "timerfd_settime",
                "timerfd_gettime" => "timerfd_gettime",
                "accept4" => "accept4",
                "signalfd4" => "signalfd4",
                "eventfd2" => "eventfd2",
                "epoll_create1" => "epoll_create1",
                "dup3" => "dup3",
                "pipe2" => "pipe2",
                "inotify_init1" => "inotify_init1",
                "preadv" => "preadv",
                "pwritev" => "pwritev",
                "rt_tgsigqueueinfo" => "rt_tgsigqueueinfo",
                "perf_event_open" => "perf_event_open",
                "recvmmsg" => "recvmmsg",
                "fanotify_init" => "fanotify_init",
                "fanotify_mark" => "fanotify_mark",
                "prlimit64" => "prlimit64",
                "name_to_handle_at" => "name_to_handle_at",
                "open_by_handle_at" => "open_by_handle_at",
                "clock_adjtime" => "clock_adjtime",
                "syncfs" => "syncfs",
                "sendmmsg" => "sendmmsg",
                "setns" => "setns",
                "getcpu" => "getcpu",
                "process_vm_readv" => "process_vm_readv",
                "process_vm_writev" => "process_vm_writev",
                "kcmp" => "kcmp",
                "finit_module" => "finit_module",
                "sched_setattr" => "sched_setattr",
                "sched_getattr" => "sched_getattr",
                "renameat2" => "renameat2",
                "seccomp" => "seccomp",
                "getrandom" => "getrandom",
                "memfd_create" => "memfd_create",
                "kexec_file_load" => "kexec_file_load",
                "bpf" => "bpf",
                "execveat" => "execveat",
                "userfaultfd" => "userfaultfd",
                "membarrier" => "membarrier",
                "mlock2" => "mlock2",
                "copy_file_range" => "copy_file_range",
                "preadv2" => "preadv2",
                "pwritev2" => "pwritev2",
                "pkey_mprotect" => "pkey_mprotect",
                "pkey_alloc" => "pkey_alloc",
                "pkey_free" => "pkey_free",
                "statx" => "statx",
                "io_pgetevents" => "io_pgetevents",
                "rseq" => "rseq",
                "pidfd_send_signal" => "pidfd_send_signal",
                "io_uring_setup" => "io_uring_setup",
                "io_uring_enter" => "io_uring_enter",
                "io_uring_register" => "io_uring_register",
                "open_tree" => "open_tree",
                "move_mount" => "move_mount",
                "fsopen" => "fsopen",
                "fsconfig" => "fsconfig",
                "fsmount" => "fsmount",
                "fspick" => "fspick",
                "pidfd_open" => "pidfd_open",
                "clone3" => "clone3",
                _ => "unknown", // default case for unknown syscalls
            })
            .filter(|&s| s != "unknown")
            .collect();
            
        return Ok(syscalls_static);
    }
    
    // If no environment variable, use a default safe subset
    Ok(vec![
        // Minimal syscalls for most applications
        "read", "write", "close", "stat", "fstat", "lstat",
        "mmap", "mprotect", "munmap", "brk", "exit", "exit_group",
        "futex", "getpid", "getuid", "gettid", "getgid", "access",
        "readlink", "readlinkat", "clock_gettime", "uname", "getrandom",
        "nanosleep", "sigaltstack", "rt_sigaction", "rt_sigprocmask",
        // File operations
        "open", "openat", "lseek", "pread64", "newfstatat", "dup", "dup2",
        // Memory management
        "mremap", "madvise", "mincore",
        // System info
        "sysinfo", "getcpu", "getrlimit",
    ])
}

/// Non-Linux placeholder for seccomp filters
#[cfg(not(all(feature = "linux", target_os = "linux")))]
pub fn apply_seccomp_filter(_profile: SecurityProfile) -> Result<()> {
    warn!("Seccomp filtering not supported on this platform. Security will be best-effort only.");
    Ok(())
}

/// Generate a BPF program for seccomp from a seccomp filter
#[cfg(all(feature = "linux", target_os = "linux"))]
pub fn generate_bpf_program(profile: SecurityProfile) -> Result<Vec<u8>> {
    // Create seccomp filter using seccompiler
    let mut rules = SeccompFilter::new(vec![], SeccompAction::KillProcess)
        .map_err(|e| anyhow!("Failed to create seccomp filter: {}", e))?;
    
    // Configure filter based on chosen security profile
    match profile {
        SecurityProfile::Basic => configure_basic_bpf(&mut rules)?,
        SecurityProfile::Moderate => configure_moderate_bpf(&mut rules)?,
        SecurityProfile::Strict => configure_strict_bpf(&mut rules)?,
        SecurityProfile::Custom => {
            // Now implemented
            configure_custom_bpf(&mut rules)?;
        }
    }
    
    // Compile the filter to BPF
    let bpf_program = export_bpf(&rules)
        .map_err(|e| anyhow!("Failed to compile seccomp filter to BPF: {}", e))?;
    
    Ok(bpf_program)
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn configure_basic_bpf(rules: &mut SeccompFilter) -> Result<()> {
    // Allow common, safe syscalls needed for most programs
    let basic_allowed = [
        // Process/thread operations
        "exit", "exit_group", "futex", "get_robust_list", "nanosleep", "clock_nanosleep",
        "sched_yield", "sigaltstack", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", 
        
        // Memory management
        "brk", "mmap", "mprotect", "munmap", "mremap", "madvise",
        
        // File operations (read-only)
        "open", "openat", "read", "readv", "pread64", "readlink", "readlinkat", "close",
        "fstat", "stat", "lstat", "newfstatat", "access", "faccessat", "getdents", "getdents64",
        
        // Basic I/O
        "write", "writev", "pwrite64", "fsync", "fdatasync",
        
        // Process information
        "getpid", "gettid", "getppid", "getuid", "geteuid", "getgid", "getegid",
        
        // Time operations
        "clock_gettime", "gettimeofday", "time",
        
        // System information
        "uname", "sysinfo", "getrandom", "getcpu",
    ];
    
    // Add allowed syscalls using seccompiler
    for syscall in basic_allowed.iter() {
        let syscall_nr = seccompiler::resolve_syscall(syscall)
            .map_err(|_| anyhow!("Unknown syscall name: {}", syscall))?;
            
        rules.add_rule(syscall_nr, vec![], SeccompAction::Allow)
            .map_err(|e| anyhow!("Failed to add rule to allow {}: {}", syscall, e))?;
    }
    
    info!("Configured basic seccomp BPF profile with {} allowed syscalls", basic_allowed.len());
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn configure_moderate_bpf(rules: &mut SeccompFilter) -> Result<()> {
    // First include all basic allowed syscalls
    configure_basic_bpf(rules)?;
    
    // Block or restrict further filesystem/network operations
    let moderate_denied = [
        // Network-related
        "socket", "socketpair", "bind", "connect", "listen", "accept", "accept4",
        "getsockname", "getpeername", "setsockopt", "getsockopt", "sendto", "recvfrom",
        "sendmsg", "recvmsg", "shutdown",
        
        // Filesystem modification
        "mkdir", "rmdir", "rename", "link", "symlink", "unlink", "chmod", "chown",
        "truncate", "ftruncate",
        
        // Process creation/control
        "clone", "fork", "vfork", "execve", "execveat", "kill", "tkill", "tgkill",
        
        // Privilege escalation
        "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid",
        "setgroups", "capset", "prctl",
        
        // System configuration
        "mount", "umount", "umount2", "pivot_root", "chroot", "swapon", "swapoff",
        "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module",
        "init_module", "delete_module", "kexec_load",
    ];
    
    // Add explicit deny rules for dangerous syscalls
    for syscall in moderate_denied.iter() {
        // Attempt to resolve the syscall number but continue if not found
        // (some might not exist on certain architectures)
        if let Ok(syscall_nr) = seccompiler::resolve_syscall(syscall) {
            rules.add_rule(syscall_nr, vec![], SeccompAction::KillProcess)
                .map_err(|e| anyhow!("Failed to add rule to deny {}: {}", syscall, e))?;
        } else {
            warn!("Syscall {} not found on this architecture, skipping", syscall);
        }
    }
    
    info!("Configured moderate seccomp BPF profile with {} explicitly denied syscalls", moderate_denied.len());
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn configure_strict_bpf(rules: &mut SeccompFilter) -> Result<()> {
    // For strict mode, first set default action to kill process
    // Then specifically allow only necessary syscalls
    
    let strict_allowed = [
        // Absolutely essential syscalls
        "exit", "exit_group", "brk", "mmap", "munmap", "mprotect",
        "read", "write", "close", "fstat", "clock_gettime",
    ];
    
    // Add only these syscalls to the allow list
    for syscall in strict_allowed.iter() {
        let syscall_nr = seccompiler::resolve_syscall(syscall)
            .map_err(|_| anyhow!("Unknown syscall name: {}", syscall))?;
            
        rules.add_rule(syscall_nr, vec![], SeccompAction::Allow)
            .map_err(|e| anyhow!("Failed to add rule to allow {}: {}", syscall, e))?;
    }
    
    info!("Configured strict seccomp BPF profile with only {} allowed syscalls", strict_allowed.len());
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn configure_custom_bpf(rules: &mut SeccompFilter) -> Result<()> {
    // Get configured syscalls from environment or configuration
    let allowed_syscalls = get_custom_syscall_allowlist()?;
    
    // Add rules for each allowed syscall
    for syscall in &allowed_syscalls {
        let syscall_nr = seccompiler::resolve_syscall(syscall)
            .map_err(|_| anyhow!("Unknown syscall name: {}", syscall))?;
            
        rules.add_rule(syscall_nr, vec![], SeccompAction::Allow)
            .map_err(|e| anyhow!("Failed to add rule for {}: {}", syscall, e))?;
    }
    
    info!("Configured custom BPF filter with {} allowed syscalls", allowed_syscalls.len());
    Ok(())
}

/// Non-Linux placeholder for BPF program generation
#[cfg(not(all(feature = "linux", target_os = "linux")))]
pub fn generate_bpf_program(_profile: SecurityProfile) -> Result<Vec<u8>> {
    Err(anyhow!("Seccomp BPF generation not supported on this platform"))
} 