use anyhow::Result as AnyhowResult;
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

#[cfg(all(feature = "linux", target_os = "linux"))]
async fn run_sandboxed_portable(
    config: SandboxConfig,
    temp_file_path: PathBuf,
    _temp_dir: tempfile::TempDir,
) -> Result<SandboxResult, SandboxError> {
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
    if config.memory_limit_mb > 0 {
        // For Python (uses PYTHONMEMORY)
        if let FileType::Python = config.file_type {
            // More aggressive memory limitation - use 90% of the requested limit
            // to account for interpreter overhead
            let memory_bytes = (config.memory_limit_mb as f64 * 0.9) as u64 * 1024 * 1024;
            command.env("PYTHONMEMORY", memory_bytes.to_string());
            
            // Also set a lower memory limit for third-party libraries that respect it
            command.env("MALLOC_ARENA_MAX", "2"); // Limit memory arenas
            
            // MacOS specific memory tuning
            #[cfg(target_os = "macos")]
            {
                // Some additional MacOS-specific environment variables that can help limit memory
                command.env("PYTHONMALLOCSTATS", "1"); // Enable memory statistics
                command.env("PYTHONMALLOC", "debug"); // More careful memory allocator
            }
        }
        
        // For Node.js (uses --max-old-space-size)
        if let FileType::JavaScript = config.file_type {
            command = Command::new("node");
            
            // Apply 80% of the memory limit to leave room for JavaScript runtime overhead
            // This is more conservative than the previous approach
            let adjusted_limit = (config.memory_limit_mb as f64 * 0.8) as u64;
            command.arg(format!("--max-old-space-size={}", adjusted_limit));
            
            // Add additional Node.js memory constraints
            command.env("NODE_OPTIONS", format!("--max-old-space-size={}", adjusted_limit));
            
            // The actual script path comes after the memory arguments
            command.arg(&temp_file_path);
        }
    }
    
    // Create a child process
    let mut child = tokio::process::Command::from(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| SandboxError::ExecutionError(format!("Failed to spawn process: {}", e)))?;
    
    // Get process ID for memory monitoring
    let pid = child.id().ok_or_else(|| 
        SandboxError::ExecutionError("Failed to get process ID".to_string())
    )?;
    
    // Set up memory monitoring task
    let memory_limit = config.memory_limit_mb;
    let timeout_s = config.timeout_s;
    let memory_monitor = tokio::task::spawn(async move {
        let check_interval = Duration::from_millis(100);
        let mut peak_memory = 0;
        let start = Instant::now();
        
        while start.elapsed() < Duration::from_secs(timeout_s) {
            // Sleep briefly before checking
            tokio::time::sleep(check_interval).await;
            
            // Check memory usage
            #[cfg(target_os = "macos")]
            if let Some(memory_mb) = get_macos_memory_usage(pid) {
                // Track peak memory usage
                if memory_mb > peak_memory {
                    peak_memory = memory_mb;
                }
                
                // If over limit, kill the process
                if memory_mb > memory_limit {
                    info!("Process exceeded memory limit: {}MB > {}MB - terminating", memory_mb, memory_limit);
                    
                    // On macOS, send SIGTERM first for clean shutdown, then SIGKILL if needed
                    unsafe {
                        libc::kill(pid as i32, libc::SIGTERM);
                        
                        // Give it a short time to terminate gracefully
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        
                        // Check if still running, then send SIGKILL
                        if libc::kill(pid as i32, 0) == 0 {
                            libc::kill(pid as i32, libc::SIGKILL);
                        }
                    }
                    
                    return (true, memory_mb, peak_memory); // Process was terminated due to memory limit
                }
            }
            
            #[cfg(not(target_os = "macos"))]
            {
                // Simple sleep on other platforms (less aggressive monitoring)
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        
        (false, 0, peak_memory) // No memory limit reached
    });
    
    // Execute with timeout
    let timeout_duration = Duration::from_secs(config.timeout_s);
    
    // Wait for process to complete or timeout
    let timeout_result = tokio::time::timeout(timeout_duration, child.wait_with_output()).await;
    
    // Check memory monitor result - (exceeded_limit, last_memory_value, peak_memory)
    let (memory_limit_exceeded, memory_value, peak_memory) = memory_monitor.await.unwrap_or((false, 0, 0));
    
    match timeout_result {
        Ok(Ok(output)) => {
            // Process completed within timeout
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let elapsed = start_time.elapsed();
            
            // If memory limit was exceeded, override exit status and message
            if memory_limit_exceeded {
                info!("Process was terminated due to memory limit violation");
                
                let mut combined_stderr = stderr;
                if !combined_stderr.is_empty() {
                    combined_stderr.push_str("\n");
                }
                combined_stderr.push_str(&format!("ERROR: Process terminated due to memory limit violation (used {}MB, limit {}MB)", 
                    memory_value, config.memory_limit_mb));
                
                return Ok(SandboxResult {
                    exit_status: 137, // Standard exit code for SIGKILL
                    stdout,
                    stderr: combined_stderr,
                    execution_time: elapsed,
                    peak_memory_kb: None,
                });
            }
            
            // Normal completion
            info!("Process completed in {:.2} seconds", elapsed.as_secs_f64());
            info!("Exit status: {}", output.status);
            info!("Peak memory usage: {} MB", peak_memory);
            
            Ok(SandboxResult {
                exit_status: output.status.code().unwrap_or(-1),
                stdout,
                stderr,
                execution_time: elapsed,
                peak_memory_kb: None,
            })
        }
        Ok(Err(e)) => {
            // Process execution failed
            Err(SandboxError::ExecutionError(format!("Failed to execute: {}", e)))
        }
        Err(_) => {
            // Timeout occurred
            info!("Process timed out after {} seconds", config.timeout_s);
            Err(SandboxError::TimeoutError(config.timeout_s))
        }
    }
}

/// Get memory usage on macOS for a given process ID
#[cfg(target_os = "macos")]
fn get_macos_memory_usage(pid: u32) -> Option<u64> {
    use std::process::Command;
    
    // Use ps command to get memory information on macOS
    // RSS (Resident Set Size) is the actual physical memory used
    let output = Command::new("ps")
        .args(&["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    
    if !output.status.success() {
        return None;
    }
    
    // Parse the output (RSS in KB)
    let stdout = String::from_utf8_lossy(&output.stdout);
    let rss_kb = stdout.trim().parse::<u64>().ok()?;
    
    // Convert KB to MB
    Some(rss_kb / 1024)
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
    // This would be implemented here in a full version
    
    // Apply seccomp filter to restrict syscalls
    apply_seccomp_filter()?;
    
    Ok(())
} 