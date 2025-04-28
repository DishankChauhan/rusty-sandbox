use anyhow::{Result, anyhow, Context};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::tempdir;
use thiserror::Error;
use tracing::{info, error, warn};
use std::collections::HashMap;

use crate::linter;
use crate::resources;

#[cfg(all(feature = "linux", target_os = "linux"))]
use std::os::unix::io::{FromRawFd, IntoRawFd};
#[cfg(all(feature = "linux", target_os = "linux"))]
use nix::unistd::{fork, ForkResult};
#[cfg(all(feature = "linux", target_os = "linux"))]
use nix::sys::wait::{waitpid, WaitStatus};
#[cfg(all(feature = "linux", target_os = "linux"))]
use nix::sys::resource::{setrlimit, Resource, Rlim};
#[cfg(all(feature = "linux", target_os = "linux"))]
use nix::unistd::Pid;
#[cfg(all(feature = "linux", target_os = "linux"))]
use seccompiler::{SeccompFilter, SeccompAction};

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("Failed to fork process: {0}")]
    #[cfg(all(feature = "linux", target_os = "linux"))]
    ForkError(#[from] nix::Error),
    
    #[error("Failed to set resource limits: {0}")]
    ResourceLimitError(String),
    
    #[error("Failed to execute command: {0}")]
    ExecutionError(String),
    
    #[error("Execution timed out after {0} seconds")]
    TimeoutError(u64),
    
    #[error("Memory limit exceeded: {0} MB (limit was {1} MB)")]
    MemoryLimitExceeded(u64, u64),
    
    #[error("Failed to read file: {0}")]
    FileReadError(#[from] std::io::Error),
    
    #[error("Static analysis found dangerous code: {0}")]
    LinterError(String),
    
    #[error("This feature is only available on Linux: {0}")]
    PlatformError(String),
    
    #[error("Tokio error: {0}")]
    TokioError(String),
    
    #[error("Other error: {0}")]
    OtherError(String),
}

impl From<tokio::task::JoinError> for SandboxError {
    fn from(err: tokio::task::JoinError) -> Self {
        SandboxError::TokioError(err.to_string())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FileType {
    Python,
    JavaScript,
}

#[derive(Debug)]
pub struct SandboxConfig {
    pub file_path: PathBuf,
    pub file_type: FileType,
    pub memory_limit_mb: u64,
    pub cpu_time_limit_s: u64,
    pub timeout_s: u64,
}

#[derive(Debug, Clone)]
pub struct SandboxResult {
    pub exit_status: i32,
    pub stdout: String,
    pub stderr: String,
    pub execution_time: Duration,
    pub peak_memory_kb: Option<u64>,
}

pub async fn run_sandboxed(config: SandboxConfig) -> Result<SandboxResult, SandboxError> {
    // Read file content
    let mut file = File::open(&config.file_path)
        .map_err(|e| SandboxError::FileReadError(e))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| SandboxError::FileReadError(e))?;
    
    // Static analysis check
    linter::check_for_dangerous_code(&content, config.file_type)
        .map_err(|err| SandboxError::LinterError(err.to_string()))?;
    
    // Create temporary directory for execution
    let temp_dir = tempdir()
        .map_err(|e| SandboxError::FileReadError(e))?;
    
    // Copy the file to temporary directory
    let temp_file_path = temp_dir.path().join(
        config.file_path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("script"))
    );
    let mut temp_file = File::create(&temp_file_path)
        .map_err(|e| SandboxError::FileReadError(e))?;
    temp_file.write_all(content.as_bytes())
        .map_err(|e| SandboxError::FileReadError(e))?;
    
    #[cfg(all(feature = "linux", target_os = "linux"))]
    {
        run_sandboxed_linux(config, temp_file_path, temp_dir).await
    }
    
    #[cfg(not(all(feature = "linux", target_os = "linux")))]
    {
        run_sandboxed_portable(config, temp_file_path, temp_dir).await
    }
}

#[cfg(all(feature = "linux", target_os = "linux"))]
async fn run_sandboxed_linux(
    config: SandboxConfig,
    temp_file_path: PathBuf,
    _temp_dir: tempfile::TempDir,
) -> Result<SandboxResult, SandboxError> {
    // Create pipes for stdout and stderr
    let (stdout_read, stdout_write) = nix::unistd::pipe()
        .map_err(|e| SandboxError::ForkError(e))?;
    let (stderr_read, stderr_write) = nix::unistd::pipe()
        .map_err(|e| SandboxError::ForkError(e))?;
    
    let start_time = Instant::now();
    
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Close write ends of pipes in parent
            nix::unistd::close(stdout_write).unwrap();
            nix::unistd::close(stderr_write).unwrap();
            
            // Convert to Files
            let mut stdout_file = unsafe { File::from_raw_fd(stdout_read) };
            let mut stderr_file = unsafe { File::from_raw_fd(stderr_read) };
            
            let mut stdout_content = String::new();
            let mut stderr_content = String::new();
            
            // Set timeout
            let timeout_duration = Duration::from_secs(config.timeout_s);
            
            // Start resource monitoring in a separate thread
            let resource_monitoring = tokio::task::spawn_blocking(move || {
                // Allow the process to initialize before monitoring
                std::thread::sleep(Duration::from_millis(100));
                
                // Monitor resources for the duration of execution up to the timeout
                if let Ok(stats) = resources::monitor_resources(child, timeout_duration) {
                    // If resource monitoring succeeded, print a report
                    resources::print_resource_report(&stats);
                    return stats;
                }
                
                // Return default stats if monitoring failed
                resources::ResourceStats {
                    peak_memory_mb: 0,
                    cpu_time_used_s: 0.0,
                    wall_time_used_s: 0.0,
                }
            });
            
            // Wait for child with timeout
            let wait_result = tokio::task::spawn_blocking(move || {
                let start = Instant::now();
                loop {
                    if start.elapsed() > timeout_duration {
                        // Kill child if timeout
                        nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL).ok();
                        return Err(SandboxError::TimeoutError(config.timeout_s));
                    }
                    
                    match waitpid(child, None) {
                        Ok(WaitStatus::Exited(_, status)) => {
                            stdout_file.read_to_string(&mut stdout_content).ok();
                            stderr_file.read_to_string(&mut stderr_content).ok();
                            
                            return Ok(SandboxResult {
                                exit_status: status,
                                stdout: stdout_content,
                                stderr: stderr_content,
                                execution_time: start.elapsed(),
                                peak_memory_kb: Some(0),
                            });
                        }
                        Ok(WaitStatus::Signaled(_, signal, _)) => {
                            stdout_file.read_to_string(&mut stdout_content).ok();
                            stderr_file.read_to_string(&mut stderr_content).ok();
                            
                            let stderr_msg = format!("Process terminated by signal: {}", signal);
                            if stderr_content.is_empty() {
                                stderr_content = stderr_msg;
                            } else {
                                stderr_content = format!("{}\n{}", stderr_content, stderr_msg);
                            }
                            
                            return Ok(SandboxResult {
                                exit_status: 128 + signal as i32,
                                stdout: stdout_content,
                                stderr: stderr_content,
                                execution_time: start.elapsed(),
                                peak_memory_kb: Some(0),
                            });
                        }
                        Err(e) => {
                            return Err(SandboxError::ExecutionError(format!("waitpid error: {}", e)));
                        }
                        _ => {
                            // Continue waiting
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            }).await?;
            
            // Wait for resource monitoring to complete
            let _ = resource_monitoring.await;
            
            wait_result
        }
        Ok(ForkResult::Child) => {
            // Close read ends of pipes in child
            nix::unistd::close(stdout_read).unwrap();
            nix::unistd::close(stderr_read).unwrap();
            
            // Redirect stdout and stderr
            nix::unistd::dup2(stdout_write, 1).unwrap();
            nix::unistd::dup2(stderr_write, 2).unwrap();
            
            // Close the duplicated file descriptors
            nix::unistd::close(stdout_write).unwrap();
            nix::unistd::close(stderr_write).unwrap();
            
            // Apply Linux-specific security features
            apply_linux_security_features(&config)?;
            
            // Execute the program
            execute_program(&temp_file_path, config.file_type)?;
            
            // This should not be reached if exec succeeds
            std::process::exit(1);
        }
        Err(e) => {
            return Err(SandboxError::ForkError(e));
        }
    }
}

#[cfg(not(all(feature = "linux", target_os = "linux")))]
async fn run_sandboxed_portable(
    config: SandboxConfig,
    temp_file_path: PathBuf,
    _temp_dir: tempfile::TempDir,
) -> Result<SandboxResult, SandboxError> {
    use std::process::Stdio;
    use tokio::process::Command;
    use tokio::time::timeout;
    
    info!("Running in portable mode (without Linux-specific security features)");
    
    #[cfg(target_os = "macos")]
    info!("Running on macOS - using enhanced memory monitoring");
    
    let start_time = Instant::now();
    
    // Create command for execution
    let mut command = match config.file_type {
        FileType::Python => Command::new("python3"),
        FileType::JavaScript => Command::new("node"),
    };
    
    command.arg(&temp_file_path);
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    
    // Apply memory limits using environment variables
    // This is platform-independent and works with many language runtimes
    command.env("NODE_OPTIONS", format!("--max-old-space-size={}", config.memory_limit_mb));
    command.env("PYTHONMALLOC", "malloc");
    
    // Spawn the process
    let mut child = command
        .spawn()
        .map_err(|e| SandboxError::ExecutionError(format!("Failed to spawn process: {}", e)))?;
    
    // Get process ID for memory monitoring
    let pid = child.id().ok_or_else(|| 
        SandboxError::ExecutionError("Failed to get process ID".to_string())
    )?;
    
    // Set up memory monitoring task
    let memory_limit = config.memory_limit_mb;
    let memory_monitor_handle = tokio::task::spawn(async move {
        let check_interval = Duration::from_millis(100);
        let mut peak_memory = 0;
        
        loop {
            tokio::time::sleep(check_interval).await;
            
            // Check memory usage using OS-specific methods
            #[cfg(target_os = "macos")]
            {
                if let Ok(memory) = resources::get_memory_usage_macos(pid) {
                    peak_memory = peak_memory.max(memory);
                    
                    // Check if exceeding limit
                    if memory > memory_limit * 1024 {
                        return Err(SandboxError::MemoryLimitExceeded(memory / 1024, memory_limit));
                    }
                } else {
                    // Process may have ended
                    break;
                }
            }
            
            #[cfg(target_os = "linux")]
            {
                if let Ok(memory) = resources::get_memory_usage_linux(pid) {
                    peak_memory = peak_memory.max(memory);
                    
                    // Check if exceeding limit
                    if memory > memory_limit * 1024 {
                        return Err(SandboxError::MemoryLimitExceeded(memory / 1024, memory_limit));
                    }
                } else {
                    // Process may have ended
                    break;
                }
            }
            
            // Generic fallback for other platforms
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                // Just break the loop on unsupported platforms
                break;
            }
        }
        
        Ok(peak_memory)
    });
    
    // Wait for the process with timeout
    let timeout_duration = Duration::from_secs(config.timeout_s);
    
    // Store the child ID for later killing if needed
    let child_id = child.id();
    
    // Wait for the process with timeout
    let result = timeout(timeout_duration, child.wait_with_output()).await;
    
    // Process the result
    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            
            // Try to get memory usage results
            let peak_memory = match memory_monitor_handle.await {
                Ok(Ok(mem)) => Some(mem),
                Ok(Err(SandboxError::MemoryLimitExceeded(_, _))) => {
                    // Memory limit was exceeded, but process completed anyway
                    // Return the output with an error code
                    return Ok(SandboxResult {
                        exit_status: 1,
                        stdout,
                        stderr: format!("{}\nMemory limit exceeded", stderr),
                        execution_time: start_time.elapsed(),
                        peak_memory_kb: None,
                    });
                },
                _ => None,
            };
            
            Ok(SandboxResult {
                exit_status: output.status.code().unwrap_or(1),
                stdout,
                stderr,
                execution_time: start_time.elapsed(),
                peak_memory_kb: peak_memory,
            })
        },
        Ok(Err(e)) => {
            Err(SandboxError::ExecutionError(format!("Failed to execute: {}", e)))
        },
        Err(_) => {
            // Timeout occurred
            // Try to kill the process using the stored ID
            if let Some(id) = child_id {
                // Use platform-specific methods to kill the process
                #[cfg(target_os = "macos")]
                {
                    use std::process::Command;
                    let _ = Command::new("kill")
                        .arg("-9")
                        .arg(id.to_string())
                        .output();
                }
                
                #[cfg(target_os = "linux")]
                {
                    use std::process::Command;
                    let _ = Command::new("kill")
                        .arg("-9")
                        .arg(id.to_string())
                        .output();
                }
            }
            
            Err(SandboxError::TimeoutError(config.timeout_s))
        },
    }
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn set_resource_limits_linux(memory_limit_mb: u64, cpu_time_limit_s: u64) -> Result<(), SandboxError> {
    // Set memory limit (in bytes)
    let memory_limit_bytes = memory_limit_mb * 1024 * 1024;
    if let Err(e) = setrlimit(Resource::RLIMIT_AS, Rlim::from_raw(memory_limit_bytes), Rlim::from_raw(memory_limit_bytes)) {
        return Err(SandboxError::ResourceLimitError(format!("Failed to set memory limit: {}", e)));
    }
    
    // Set CPU time limit
    if let Err(e) = setrlimit(Resource::RLIMIT_CPU, Rlim::from_raw(cpu_time_limit_s), Rlim::from_raw(cpu_time_limit_s)) {
        return Err(SandboxError::ResourceLimitError(format!("Failed to set CPU limit: {}", e)));
    }
    
    // Set process limit (prevent fork bombs)
    if let Err(e) = setrlimit(Resource::RLIMIT_NPROC, Rlim::from_raw(10), Rlim::from_raw(10)) {
        return Err(SandboxError::ResourceLimitError(format!("Failed to set process limit: {}", e)));
    }
    
    // Set file size limit
    if let Err(e) = setrlimit(Resource::RLIMIT_FSIZE, Rlim::from_raw(50 * 1024 * 1024), Rlim::from_raw(50 * 1024 * 1024)) {
        return Err(SandboxError::ResourceLimitError(format!("Failed to set file size limit: {}", e)));
    }
    
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn apply_seccomp_filter() -> Result<(), SandboxError> {
    info!("Applying seccomp filters to restrict system calls");
    
    // Define a seccomp filter that allows only necessary syscalls
    let filter = match create_seccomp_filter() {
        Ok(f) => f,
        Err(e) => return Err(SandboxError::ResourceLimitError(format!("Failed to create seccomp filter: {}", e))),
    };
    
    // Apply the filter
    if let Err(e) = apply_filter(filter) {
        return Err(SandboxError::ResourceLimitError(format!("Failed to apply seccomp filter: {}", e)));
    }
    
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn create_seccomp_filter() -> Result<SeccompFilter, String> {
    use seccompiler::{BpfProgram, SeccompRule, SeccompCmpArgLen, SeccompCmpOp};
    
    // Create a default seccomp filter context
    let mut rules = HashMap::new();
    
    // Allow essential syscalls
    let essential_syscalls = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_uname,
        libc::SYS_fcntl,
        libc::SYS_getrlimit,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_arch_prctl,
        libc::SYS_access,
        libc::SYS_gettid,
        libc::SYS_clone,
        libc::SYS_execve,
        libc::SYS_lseek,
        libc::SYS_getcwd,
        libc::SYS_getpid,
    ];
    
    // Add each essential syscall to the rules
    for syscall in essential_syscalls {
        rules.insert(syscall, vec![SeccompRule::new(vec![], SeccompAction::Allow)]);
    }
    
    // Disallow all other syscalls
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM),  // Return "operation not permitted" for disallowed syscalls
        SeccompAction::Allow,  // Default action (not used due to explicit default action)
    ).map_err(|e| format!("Failed to create seccomp filter: {}", e))?;
    
    Ok(filter)
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn apply_filter(filter: SeccompFilter) -> Result<(), String> {
    // Compile the seccomp filter to BPF
    let bpf_program = filter.try_into_bpf_prog()
        .map_err(|e| format!("Failed to compile seccomp filter to BPF: {}", e))?;
    
    // Set no_new_privs to 1
    // This prevents the process from gaining privileges (e.g., via setuid binaries)
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(format!("Failed to set PR_SET_NO_NEW_PRIVS: {}", std::io::Error::last_os_error()));
    }
    
    // Load the BPF program
    // This sets the process to use the specified seccomp filter
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            bpf_program.as_ptr() as u64,
            0,
            0,
        )
    };
    
    if rc != 0 {
        return Err(format!("Failed to apply seccomp filter: {}", std::io::Error::last_os_error()));
    }
    
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn create_namespaces() -> Result<(), SandboxError> {
    info!("Creating Linux namespaces for isolation");
    
    // Create new user namespace
    // This allows unprivileged users to create other namespaces
    let unshare_flags = libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWNET | libc::CLONE_NEWNS | libc::CLONE_NEWIPC;
    
    if unsafe { libc::unshare(unshare_flags) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(SandboxError::PlatformError(format!("Failed to create namespaces: {}", err)));
    }
    
    // Set up UID/GID mapping for user namespace
    // This maps the unprivileged user to root inside the namespace
    setup_idmap().map_err(|e| SandboxError::PlatformError(format!("Failed to set up UID/GID mapping: {}", e)))?;
    
    // Remount /proc to get accurate PID view
    if unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(SandboxError::PlatformError(format!("Failed to create PID namespace: {}", err)));
    }
    
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn setup_idmap() -> Result<(), String> {
    // Get current UID and GID
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    
    // Write UID map (format: "inside-uid outside-uid count")
    // Maps UID 0 inside the namespace to the current UID outside
    let uid_map = format!("0 {} 1", uid);
    write_to_proc_file("/proc/self/uid_map", &uid_map)?;
    
    // Disable setgroups to be able to write GID map
    write_to_proc_file("/proc/self/setgroups", "deny")?;
    
    // Write GID map
    // Maps GID 0 inside the namespace to the current GID outside
    let gid_map = format!("0 {} 1", gid);
    write_to_proc_file("/proc/self/gid_map", &gid_map)?;
    
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn write_to_proc_file(path: &str, content: &str) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::io::Write;
    
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("Failed to open {}: {}", path, e))?;
    
    file.write_all(content.as_bytes())
        .map_err(|e| format!("Failed to write to {}: {}", path, e))?;
    
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn execute_program(file_path: &PathBuf, file_type: FileType) -> Result<(), SandboxError> {
    let mut command = match file_type {
        FileType::Python => Command::new("python3"),
        FileType::JavaScript => Command::new("node"),
    };
    
    command.arg(file_path);
    command.stdin(Stdio::null());
    
    let error = command
        .exec()
        .to_string();
    
    Err(SandboxError::ExecutionError(error))
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn apply_linux_security_features(config: &SandboxConfig) -> Result<(), SandboxError> {
    // Set resource limits first (must be done before dropping privileges)
    set_resource_limits_linux(config.memory_limit_mb, config.cpu_time_limit_s)?;
    
    // Create new namespaces for isolation
    create_namespaces()?;
    
    // Change root to temporary directory for filesystem isolation
    apply_filesystem_isolation()?;
    
    // Apply seccomp filter to restrict syscalls
    apply_seccomp_filter()?;
    
    Ok(())
}

/// Apply filesystem isolation using chroot or mount namespaces
#[cfg(all(feature = "linux", target_os = "linux"))]
fn apply_filesystem_isolation() -> Result<(), SandboxError> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use nix::unistd::{chroot, chdir};
    use nix::mount::{mount, MsFlags};
    use tempfile::TempDir;
    
    // Create a temporary directory for the chroot environment
    let chroot_dir = TempDir::new()
        .map_err(|e| SandboxError::OtherError(format!("Failed to create chroot directory: {}", e)))?;
    
    // Create necessary directories in the chroot environment
    let dirs = ["bin", "lib", "lib64", "usr", "tmp", "dev", "proc"];
    for dir in &dirs {
        let path = chroot_dir.path().join(dir);
        fs::create_dir_all(&path)
            .map_err(|e| SandboxError::OtherError(format!("Failed to create directory {}: {}", path.display(), e)))?;
        
        // Set appropriate permissions
        let metadata = fs::metadata(&path)
            .map_err(|e| SandboxError::OtherError(format!("Failed to get metadata for {}: {}", path.display(), e)))?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o755); // rwxr-xr-x
        fs::set_permissions(&path, perms)
            .map_err(|e| SandboxError::OtherError(format!("Failed to set permissions for {}: {}", path.display(), e)))?;
    }
    
    // Mount /proc in the chroot for process information
    let proc_path = chroot_dir.path().join("proc");
    mount(
        Some("proc"),
        &proc_path,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    ).map_err(|e| SandboxError::OtherError(format!("Failed to mount proc: {}", e)))?;
    
    // Mount /dev in the chroot for essential device files
    let dev_path = chroot_dir.path().join("dev");
    mount(
        Some("tmpfs"),
        &dev_path,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        None::<&str>,
    ).map_err(|e| SandboxError::OtherError(format!("Failed to mount dev: {}", e)))?;
    
    // Create essential device nodes in /dev
    // /dev/null
    let null_path = dev_path.join("null");
    fs::File::create(&null_path)
        .map_err(|e| SandboxError::OtherError(format!("Failed to create /dev/null: {}", e)))?;
    nix::sys::stat::mknod(&null_path, nix::sys::stat::SFlag::S_IFCHR, 0o666, nix::sys::stat::makedev(1, 3))
        .map_err(|e| SandboxError::OtherError(format!("Failed to create /dev/null device: {}", e)))?;
    
    // /dev/zero
    let zero_path = dev_path.join("zero");
    fs::File::create(&zero_path)
        .map_err(|e| SandboxError::OtherError(format!("Failed to create /dev/zero: {}", e)))?;
    nix::sys::stat::mknod(&zero_path, nix::sys::stat::SFlag::S_IFCHR, 0o666, nix::sys::stat::makedev(1, 5))
        .map_err(|e| SandboxError::OtherError(format!("Failed to create /dev/zero device: {}", e)))?;
    
    // /dev/urandom
    let urandom_path = dev_path.join("urandom");
    fs::File::create(&urandom_path)
        .map_err(|e| SandboxError::OtherError(format!("Failed to create /dev/urandom: {}", e)))?;
    nix::sys::stat::mknod(&urandom_path, nix::sys::stat::SFlag::S_IFCHR, 0o666, nix::sys::stat::makedev(1, 9))
        .map_err(|e| SandboxError::OtherError(format!("Failed to create /dev/urandom device: {}", e)))?;
    
    // Create a directory for the executable and its dependencies
    let exec_dir = chroot_dir.path().join("app");
    fs::create_dir_all(&exec_dir)
        .map_err(|e| SandboxError::OtherError(format!("Failed to create app directory: {}", e)))?;
    
    // Change root to the temporary directory
    chroot(chroot_dir.path())
        .map_err(|e| SandboxError::OtherError(format!("Failed to chroot: {}", e)))?;
    
    // Change current directory to /app within the chroot
    chdir("/app")
        .map_err(|e| SandboxError::OtherError(format!("Failed to change directory: {}", e)))?;
    
    // The temporary directory will be automatically cleaned up when it goes out of scope
    // But since we've chrooted, the cleanup will happen when the process exits
    
    // Prevent the TempDir from being dropped and removed
    // (the OS will clean it up when the process exits)
    std::mem::forget(chroot_dir);
    
    Ok(())
}

// Implementation for macOS
#[cfg(target_os = "macos")]
fn apply_filesystem_isolation() -> Result<(), SandboxError> {
    // On macOS, we rely on the sandbox-exec mechanism implemented in security.rs
    // macOS doesn't support chroot for non-root users, so we use the built-in sandbox feature
    info!("Using macOS sandbox for filesystem isolation");
    Ok(())
}

// Generic implementation for other platforms
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn apply_filesystem_isolation() -> Result<(), SandboxError> {
    warn!("Filesystem isolation not fully supported on this platform");
    Ok(())
}

/// Terminate a process by its PID
fn terminate_process(pid: i32, force: bool) -> Result<()> {
    // Store the child ID for later killing if needed
    #[cfg(target_family = "unix")]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        
        let signal = if force {
            Signal::SIGKILL
        } else {
            Signal::SIGTERM
        };
        
        // Send signal to process group to terminate all children
        let result = kill(Pid::from_raw(-pid), signal);
        
        if let Err(e) = result {
            // Only report error if process still exists
            if e != nix::Error::ESRCH {
                return Err(anyhow!("Failed to terminate process {}: {}", pid, e));
            }
        }
        
        // Wait a bit for process to terminate
        let wait_time = if force {
            std::time::Duration::from_millis(100)
        } else {
            std::time::Duration::from_millis(500)
        };
        
        std::thread::sleep(wait_time);
        
        // Check if process still exists
        if process_exists(pid) {
            if !force {
                // Try again with SIGKILL
                warn!("Process {} didn't terminate with SIGTERM, trying SIGKILL", pid);
                return terminate_process(pid, true);
            } else {
                return Err(anyhow!("Failed to terminate process {} even with SIGKILL", pid));
            }
        }
        
        Ok(())
    }
    
    #[cfg(not(target_family = "unix"))]
    {
        // Windows or other non-Unix platforms
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            
            // On Windows, use taskkill
            let args = if force {
                ["/F", "/T", "/PID", &pid.to_string()]
            } else {
                ["/T", "/PID", &pid.to_string()]
            };
            
            let output = Command::new("taskkill")
                .args(&args)
                .output()
                .context("Failed to execute taskkill command")?;
                
            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                if !error.contains("not found") && !error.contains("not running") {
                    return Err(anyhow!("Failed to terminate process {}: {}", pid, error));
                }
            }
            
            Ok(())
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Process termination not implemented for this platform"))
        }
    }
}

/// Check if a process exists
fn process_exists(pid: i32) -> bool {
    #[cfg(target_family = "unix")]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        
        // Send signal 0 to check if process exists
        kill(Pid::from_raw(pid), Signal::SIGCONT).is_ok()
    }
    
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        // On Windows, use tasklist to check if process exists
        let output = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/NH"])
            .output();
            
        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout.contains(&pid.to_string())
            },
            Err(_) => false,
        }
    }
    
    #[cfg(not(any(target_family = "unix", target_os = "windows")))]
    {
        // Default implementation for other platforms - use sysinfo
        use sysinfo::{System, SystemExt, ProcessExt, PidExt};
        
        let mut system = System::new_all();
        system.refresh_all();
        
        let sys_pid = sysinfo::Pid::from_u32(pid as u32);
        system.process(sys_pid).is_some()
    }
}

/// Get the command line of a process
fn get_process_command(pid: i32) -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        use std::fs::read_to_string;
        use std::path::Path;
        
        // Read from /proc/<pid>/cmdline
        let cmdline_path = Path::new("/proc").join(pid.to_string()).join("cmdline");
        let cmdline = read_to_string(cmdline_path)
            .with_context(|| format!("Failed to read command line for process {}", pid))?;
            
        // /proc/cmdline uses null bytes as separators
        let cmd = cmdline.replace('\0', " ").trim().to_string();
        Ok(cmd)
    }
    
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        
        // Use ps on macOS
        let output = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .output()
            .context("Failed to execute ps command")?;
            
        if !output.status.success() {
            return Err(anyhow!("Failed to get command line for process {}", pid));
        }
        
        let cmd = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(cmd)
    }
    
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        // Use wmic on Windows
        let output = Command::new("wmic")
            .args(["process", "where", &format!("ProcessId={}", pid), "get", "CommandLine", "/format:list"])
            .output()
            .context("Failed to execute wmic command")?;
            
        if !output.status.success() {
            return Err(anyhow!("Failed to get command line for process {}", pid));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse out the CommandLine=<value> format
        if let Some(cmd_line) = stdout.lines()
            .find(|line| line.starts_with("CommandLine="))
            .map(|line| line.trim_start_matches("CommandLine=").trim()) {
            Ok(cmd_line.to_string())
        } else {
            Err(anyhow!("Could not parse command line for process {}", pid))
        }
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        // Default implementation for other platforms - use sysinfo
        use sysinfo::{System, SystemExt, ProcessExt, PidExt};
        
        let mut system = System::new_all();
        system.refresh_all();
        
        let sys_pid = sysinfo::Pid::from_u32(pid as u32);
        if let Some(process) = system.process(sys_pid) {
            Ok(process.cmd().join(" "))
        } else {
            Err(anyhow!("Process {} not found", pid))
        }
    }
}

/// Get children of a process
fn get_process_children(pid: i32) -> Result<Vec<i32>> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        use std::path::Path;
        
        // Find all processes with this parent
        let mut children = Vec::new();
        let proc_dir = Path::new("/proc");
        
        if let Ok(entries) = fs::read_dir(proc_dir) {
            for entry in entries.filter_map(Result::ok) {
                // Check if this is a PID directory
                if let Ok(entry_pid) = entry.file_name().to_string_lossy().parse::<i32>() {
                    // Skip the process itself
                    if entry_pid == pid {
                        continue;
                    }
                    
                    // Read status file to get parent PID
                    let status_path = entry.path().join("status");
                    if let Ok(status) = fs::read_to_string(status_path) {
                        // Look for PPid: line
                        for line in status.lines() {
                            if line.starts_with("PPid:") {
                                if let Ok(ppid) = line.trim_start_matches("PPid:").trim().parse::<i32>() {
                                    if ppid == pid {
                                        children.push(entry_pid);
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        Ok(children)
    }
    
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        
        // Use pgrep on macOS to find children
        let output = Command::new("pgrep")
            .args(["-P", &pid.to_string()])
            .output()
            .context("Failed to execute pgrep command")?;
            
        // pgrep returns non-zero if no matches, which is fine
        if !output.status.success() && !output.stdout.is_empty() {
            return Ok(Vec::new());
        }
        
        // Parse the output to get PIDs
        let stdout = String::from_utf8_lossy(&output.stdout);
        let children: Vec<i32> = stdout
            .lines()
            .filter_map(|line| line.trim().parse::<i32>().ok())
            .collect();
            
        Ok(children)
    }
    
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        // Use wmic on Windows to find children
        let output = Command::new("wmic")
            .args(["process", "where", &format!("ParentProcessId={}", pid), "get", "ProcessId", "/format:list"])
            .output()
            .context("Failed to execute wmic command")?;
            
        if !output.status.success() {
            return Err(anyhow!("Failed to get child processes for {}", pid));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Parse out the ProcessId=<value> format
        let children: Vec<i32> = stdout.lines()
            .filter(|line| line.starts_with("ProcessId="))
            .filter_map(|line| {
                line.trim_start_matches("ProcessId=").trim().parse::<i32>().ok()
            })
            .collect();
            
        Ok(children)
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        // Default implementation for other platforms - use sysinfo
        use sysinfo::{System, SystemExt, ProcessExt, PidExt};
        
        let mut system = System::new_all();
        system.refresh_all();
        
        let sys_pid = sysinfo::Pid::from_u32(pid as u32);
        
        // Find all processes with this parent
        let children: Vec<i32> = system.processes().iter()
            .filter_map(|(child_pid, process)| {
                if let Some(parent_pid) = process.parent() {
                    if parent_pid == sys_pid {
                        // Convert sysinfo Pid to i32
                        Some(child_pid.as_u32() as i32)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
            
        Ok(children)
    }
} 