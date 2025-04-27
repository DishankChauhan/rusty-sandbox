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
    
    // Create a new filter context with default action to deny
    let mut filter_ctx = ScmpFilterContext::new_filter(libseccomp::ScmpAction::KillProcess)
        .map_err(|e| anyhow!("Failed to create seccomp filter: {}", e))?;
    
    // Configure filter based on chosen security profile
    match profile {
        SecurityProfile::Basic => configure_basic_profile(&mut filter_ctx)?,
        SecurityProfile::Moderate => configure_moderate_profile(&mut filter_ctx)?,
        SecurityProfile::Strict => configure_strict_profile(&mut filter_ctx)?,
        SecurityProfile::Custom => {
            // Custom profile would be configured separately
            return Err(anyhow!("Custom seccomp profile not implemented yet"));
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
            return Err(anyhow!("Custom seccomp profile not implemented"));
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

/// Non-Linux placeholder for BPF program generation
#[cfg(not(all(feature = "linux", target_os = "linux")))]
pub fn generate_bpf_program(_profile: SecurityProfile) -> Result<Vec<u8>> {
    Err(anyhow!("Seccomp BPF generation not supported on this platform"))
} 