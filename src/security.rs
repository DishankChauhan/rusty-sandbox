use anyhow::{anyhow, Result, Context};
use log::{debug, info, warn, error};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::collections::HashSet;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::thread;
use serde::{Serialize, Deserialize};
use crate::runtime::SandboxPolicy;

/// Security level for the sandbox
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityLevel {
    /// Basic security (process isolation)
    Basic,
    /// Standard security (default)
    Standard,
    /// Enhanced security (more restrictive)
    Enhanced,
    /// Maximum security (most restrictive)
    Maximum,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Standard
    }
}

/// Network access level for language profiles
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkAccess {
    /// No network access allowed
    None,
    /// Limited network access (to specific domains)
    Limited(Vec<String>),
    /// Full network access
    Full,
}

impl Default for NetworkAccess {
    fn default() -> Self {
        NetworkAccess::None
    }
}

/// Security policy for sandboxed processes
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Security level
    pub level: SecurityLevel,
    /// Allowed executables (absolute paths)
    pub allowed_executables: HashSet<PathBuf>,
    /// Allowed paths for file access
    pub allowed_paths: HashSet<PathBuf>,
    /// Allowed domains for network access
    pub allowed_domains: HashSet<String>,
    /// Enable seccomp filtering
    pub enable_seccomp: bool,
    /// Enable network access
    pub enable_network: bool,
    /// Enable creation of child processes
    pub enable_fork: bool,
    /// Enable filesystem access
    pub enable_filesystem: bool,
    /// Maximum depth of process tree
    pub max_process_depth: u32,
    /// Path to chroot environment (if enabled)
    pub chroot_path: Option<PathBuf>,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        let mut allowed_paths = HashSet::new();
        allowed_paths.insert(PathBuf::from("/tmp"));
        allowed_paths.insert(PathBuf::from("/usr/lib"));
        allowed_paths.insert(PathBuf::from("/lib"));
        
        let mut allowed_executables = HashSet::new();
        allowed_executables.insert(PathBuf::from("/usr/bin/python3"));
        allowed_executables.insert(PathBuf::from("/usr/bin/node"));
        
        SecurityPolicy {
            level: SecurityLevel::default(),
            allowed_executables,
            allowed_paths,
            allowed_domains: HashSet::new(),
            enable_seccomp: true,
            enable_network: false,
            enable_fork: true,
            enable_filesystem: true,
            max_process_depth: 5,
            chroot_path: None,
        }
    }
}

impl SecurityPolicy {
    /// Create a security policy with the specified level
    pub fn with_level(level: SecurityLevel) -> Self {
        let mut policy = Self::default();
        policy.level = level;
        
        // Apply security level modifications
        match level {
            SecurityLevel::Basic => {
                // Basic is already covered by default
            },
            SecurityLevel::Standard => {
                // Standard is the default
            },
            SecurityLevel::Enhanced => {
                // Enhanced reduces permissions
                policy.enable_fork = false;
                policy.enable_network = false;
                policy.max_process_depth = 3;
            },
            SecurityLevel::Maximum => {
                // Maximum is very restrictive
                policy.enable_fork = false;
                policy.enable_network = false;
                policy.enable_filesystem = false;
                policy.max_process_depth = 1;
            },
        }
        
        policy
    }
    
    /// Add an allowed executable
    pub fn allow_executable<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.allowed_executables.insert(path.as_ref().to_path_buf());
        self
    }
    
    /// Add an allowed path
    pub fn allow_path<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.allowed_paths.insert(path.as_ref().to_path_buf());
        self
    }
    
    /// Add an allowed domain for network access
    pub fn allow_domain(&mut self, domain: &str) -> &mut Self {
        self.allowed_domains.insert(domain.to_string());
        self
    }
    
    /// Enable or disable network access
    pub fn set_network_access(&mut self, enable: bool) -> &mut Self {
        self.enable_network = enable;
        self
    }
    
    /// Set chroot path
    pub fn set_chroot_path<P: AsRef<Path>>(&mut self, path: Option<P>) -> &mut Self {
        self.chroot_path = path.map(|p| p.as_ref().to_path_buf());
        self
    }
}

/// Security monitor for detecting and preventing sandbox escapes
pub struct SecurityMonitor {
    /// Process ID being monitored
    pid: u32,
    /// Security policy
    policy: SecurityPolicy,
    /// Suspicious events detected
    suspicious_events: Arc<Mutex<Vec<String>>>,
    /// Whether monitoring is active
    active: Arc<Mutex<bool>>,
    /// Start time of monitoring
    start_time: Instant,
}

impl SecurityMonitor {
    /// Create a new security monitor for the given process
    pub fn new(pid: u32, policy: SecurityPolicy) -> Self {
        SecurityMonitor {
            pid,
            policy,
            suspicious_events: Arc::new(Mutex::new(Vec::new())),
            active: Arc::new(Mutex::new(false)),
            start_time: Instant::now(),
        }
    }
    
    /// Start monitoring security in a background thread
    pub fn start_monitoring(&mut self, interval_ms: u64) -> Result<()> {
        let pid = self.pid;
        let policy = self.policy.clone();
        let suspicious_events = Arc::clone(&self.suspicious_events);
        let active = Arc::clone(&self.active);
        
        // Set the active flag
        {
            let mut active_guard = active.lock().unwrap();
            *active_guard = true;
        }
        
        thread::spawn(move || {
            while *active.lock().unwrap() {
                // Check for security violations
                let violations = SecurityMonitor::check_security_violations(pid, &policy);
                
                // Add any detected violations to our list
                if let Ok(detected_violations) = violations {
                    if !detected_violations.is_empty() {
                        let mut events = suspicious_events.lock().unwrap();
                        for violation in detected_violations {
                            events.push(violation);
                        }
                    }
                }
                
                // Sleep for the interval
                thread::sleep(Duration::from_millis(interval_ms));
            }
        });
        
        Ok(())
    }
    
    /// Stop the security monitoring thread
    pub fn stop(&mut self) {
        let mut active = self.active.lock().unwrap();
        *active = false;
    }
    
    /// Get all suspicious events
    pub fn get_suspicious_events(&self) -> Vec<String> {
        self.suspicious_events.lock().unwrap().clone()
    }
    
    /// Check for security violations
    fn check_security_violations(pid: u32, policy: &SecurityPolicy) -> Result<Vec<String>> {
        let mut violations = Vec::new();
        
        // Platform-specific checks
        #[cfg(target_os = "linux")]
        {
            // Check for prohibited system calls using seccomp violations
            Self::check_seccomp_violations(pid, &mut violations)?;
            
            // Check for file access outside allowed paths
            Self::check_file_access_violations(pid, policy, &mut violations)?;
            
            // Check for network access violations
            if !policy.enable_network {
                Self::check_network_violations(pid, &mut violations)?;
            }
            
            // Check for process hierarchy violations
            Self::check_process_hierarchy_violations(pid, policy, &mut violations)?;
        }
        
        #[cfg(target_os = "macos")]
        {
            // macOS implementation
            Self::check_macos_violations(pid, policy, &mut violations)?;
        }
        
        Ok(violations)
    }
    
    #[cfg(target_os = "linux")]
    /// Check for seccomp violations in audit log
    fn check_seccomp_violations(pid: u32, violations: &mut Vec<String>) -> Result<()> {
        if let Ok(output) = Command::new("ausearch")
            .args(&["-m", "seccomp", "--start", "recent"])
            .output() {
                
            if output.status.success() {
                let log = String::from_utf8_lossy(&output.stdout);
                
                for line in log.lines() {
                    if line.contains(&format!("pid={}", pid)) {
                        violations.push(format!("Seccomp violation detected: {}", line));
                    }
                }
            }
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "linux")]
    /// Check for file access outside allowed paths
    fn check_file_access_violations(pid: u32, policy: &SecurityPolicy, violations: &mut Vec<String>) -> Result<()> {
        // Use /proc/<pid>/fd to check open files
        let fd_dir = PathBuf::from(format!("/proc/{}/fd", pid));
        
        if fd_dir.exists() {
            for entry in fs::read_dir(fd_dir)? {
                if let Ok(entry) = entry {
                    // Each entry in fd is a symlink to the actual file
                    if let Ok(target) = fs::read_link(entry.path()) {
                        // Check if the file is outside allowed paths
                        let mut allowed = false;
                        
                        for allowed_path in &policy.allowed_paths {
                            if target.starts_with(allowed_path) {
                                allowed = true;
                                break;
                            }
                        }
                        
                        if !allowed && !target.to_string_lossy().starts_with("/proc") {
                            violations.push(format!("File access outside allowed paths: {}", 
                                                  target.display()));
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "linux")]
    /// Check for network access violations
    fn check_network_violations(pid: u32, violations: &mut Vec<String>) -> Result<()> {
        // Check /proc/<pid>/net/tcp and udp
        let tcp_path = PathBuf::from(format!("/proc/{}/net/tcp", pid));
        let udp_path = PathBuf::from(format!("/proc/{}/net/udp", pid));
        
        let has_tcp = tcp_path.exists() && fs::read_to_string(&tcp_path)?.lines().count() > 1;
        let has_udp = udp_path.exists() && fs::read_to_string(&udp_path)?.lines().count() > 1;
        
        if has_tcp || has_udp {
            violations.push("Network access detected when network is disabled".to_string());
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "linux")]
    /// Check for process hierarchy violations
    fn check_process_hierarchy_violations(pid: u32, policy: &SecurityPolicy, violations: &mut Vec<String>) -> Result<()> {
        if !policy.enable_fork && Self::has_child_processes(pid)? {
            violations.push("Process forking detected when fork is disabled".to_string());
        }
        
        let process_depth = Self::get_process_tree_depth(pid)?;
        if process_depth > policy.max_process_depth {
            violations.push(format!("Process tree depth ({}) exceeds maximum allowed ({})",
                               process_depth, policy.max_process_depth));
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "linux")]
    /// Check if a process has children
    fn has_child_processes(pid: u32) -> Result<bool> {
        let mut has_children = false;
        
        if let Ok(processes) = procfs::process::all_processes() {
            for process in processes {
                if let Ok(process) = process {
                    if let Ok(stat) = process.stat() {
                        if stat.ppid == pid as i32 {
                            has_children = true;
                            break;
                        }
                    }
                }
            }
        }
        
        Ok(has_children)
    }
    
    #[cfg(target_os = "linux")]
    /// Get the depth of a process tree
    fn get_process_tree_depth(pid: u32) -> Result<u32> {
        fn get_depth_recursive(pid: i32, visited: &mut HashSet<i32>) -> u32 {
            if visited.contains(&pid) {
                return 0; // Prevent cycles
            }
            
            visited.insert(pid);
            
            let mut max_child_depth = 0;
            
            if let Ok(processes) = procfs::process::all_processes() {
                for process in processes {
                    if let Ok(process) = process {
                        if let Ok(stat) = process.stat() {
                            if stat.ppid == pid {
                                let child_depth = get_depth_recursive(stat.pid, visited);
                                max_child_depth = max_child_depth.max(child_depth);
                            }
                        }
                    }
                }
            }
            
            1 + max_child_depth
        }
        
        let mut visited = HashSet::new();
        Ok(get_depth_recursive(pid as i32, &mut visited))
    }
    
    #[cfg(target_os = "macos")]
    /// Check for security violations on macOS
    fn check_macos_violations(pid: u32, policy: &SecurityPolicy, violations: &mut Vec<String>) -> Result<()> {
        // Check open files with lsof
        if !policy.enable_filesystem {
            if let Ok(output) = Command::new("lsof")
                .args(&["-p", &pid.to_string()])
                .output() {
                
                if output.status.success() {
                    let file_list = String::from_utf8_lossy(&output.stdout);
                    
                    // Skip the header line and filter for regular files
                    for line in file_list.lines().skip(1) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 9 {
                            let file_path = parts[8];
                            
                            // Check if file is in allowed paths
                            let mut allowed = false;
                            for allowed_path in &policy.allowed_paths {
                                if Path::new(file_path).starts_with(allowed_path) {
                                    allowed = true;
                                    break;
                                }
                            }
                            
                            if !allowed && !file_path.starts_with("/dev/") {
                                violations.push(format!("File access outside allowed paths: {}", 
                                                      file_path));
                            }
                        }
                    }
                }
            }
        }
        
        // Check for network connections
        if !policy.enable_network {
            if let Ok(output) = Command::new("lsof")
                .args(&["-p", &pid.to_string(), "-i"])
                .output() {
                
                if output.status.success() && !output.stdout.is_empty() {
                    violations.push("Network access detected when network is disabled".to_string());
                }
            }
        }
        
        // Check for child processes
        if !policy.enable_fork {
            if let Ok(output) = Command::new("pgrep")
                .args(&["-P", &pid.to_string()])
                .output() {
                
                if output.status.success() && !output.stdout.is_empty() {
                    violations.push("Process forking detected when fork is disabled".to_string());
                }
            }
        }
        
        Ok(())
    }
}

/// Security breach detector for monitoring and alerting
pub struct BreachDetector {
    /// Thresholds for alerting
    thresholds: BreachThresholds,
    /// Security events detected
    events: Arc<Mutex<Vec<BreachEvent>>>,
    /// Alert callback
    alert_callback: Option<Box<dyn Fn(&BreachEvent) + Send + Sync>>,
}

/// Thresholds for breach detection
#[derive(Debug, Clone)]
pub struct BreachThresholds {
    /// Maximum number of suspicious events before alerting
    pub max_suspicious_events: usize,
    /// Maximum number of file access violations before alerting
    pub max_file_violations: usize,
    /// Maximum number of network violations before alerting
    pub max_network_violations: usize,
    /// Maximum number of process violations before alerting
    pub max_process_violations: usize,
}

impl Default for BreachThresholds {
    fn default() -> Self {
        BreachThresholds {
            max_suspicious_events: 5,
            max_file_violations: 3,
            max_network_violations: 1,
            max_process_violations: 2,
        }
    }
}

/// Security breach event
#[derive(Debug, Clone)]
pub struct BreachEvent {
    /// Type of breach
    pub breach_type: BreachType,
    /// Description of the breach
    pub description: String,
    /// Severity level
    pub severity: SeverityLevel,
    /// Process ID involved
    pub pid: u32,
    /// Timestamp of the event
    pub timestamp: u64,
}

/// Type of security breach
#[derive(Debug, Clone, PartialEq)]
pub enum BreachType {
    /// File access outside allowed paths
    FileAccess,
    /// Network access violation
    Network,
    /// Process creation/management violation
    Process,
    /// Syscall violation
    Syscall,
    /// Resource limit violation
    ResourceLimit,
    /// Other/unknown violation
    Other,
}

impl std::fmt::Display for BreachType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BreachType::FileAccess => write!(f, "FileAccess"),
            BreachType::Network => write!(f, "Network"),
            BreachType::Process => write!(f, "Process"),
            BreachType::Syscall => write!(f, "Syscall"),
            BreachType::ResourceLimit => write!(f, "ResourceLimit"),
            BreachType::Other => write!(f, "Other"),
        }
    }
}

/// Severity level of a breach
#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq)]
pub enum SeverityLevel {
    /// Informational, not a threat
    Info,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

impl BreachDetector {
    /// Create a new breach detector
    pub fn new(thresholds: BreachThresholds) -> Self {
        BreachDetector {
            thresholds,
            events: Arc::new(Mutex::new(Vec::new())),
            alert_callback: None,
        }
    }
    
    /// Set a callback to be called when a breach is detected
    pub fn set_alert_callback<F>(&mut self, callback: F)
    where
        F: Fn(&BreachEvent) + Send + Sync + 'static,
    {
        self.alert_callback = Some(Box::new(callback));
    }
    
    /// Add a security event and check for breaches
    pub fn add_event(&self, event: BreachEvent) {
        let mut events = self.events.lock().unwrap();
        events.push(event.clone());
        
        // Call the alert callback if set
        if let Some(ref callback) = self.alert_callback {
            callback(&event);
        }
    }
    
    /// Check for breaches based on recent events
    pub fn check_for_breaches(&self) -> Option<BreachEvent> {
        let events = self.events.lock().unwrap();
        
        // Count events by type
        let mut file_violations = 0;
        let mut network_violations = 0;
        let mut process_violations = 0;
        
        for event in events.iter() {
            match event.breach_type {
                BreachType::FileAccess => file_violations += 1,
                BreachType::Network => network_violations += 1,
                BreachType::Process => process_violations += 1,
                _ => {},
            }
        }
        
        // Check thresholds
        if file_violations >= self.thresholds.max_file_violations {
            return Some(BreachEvent {
                breach_type: BreachType::FileAccess,
                description: format!("Multiple file access violations detected ({})", file_violations),
                severity: SeverityLevel::High,
                pid: 0, // Aggregate event, not specific to one PID
                timestamp: chrono::Utc::now().timestamp() as u64,
            });
        }
        
        if network_violations >= self.thresholds.max_network_violations {
            return Some(BreachEvent {
                breach_type: BreachType::Network,
                description: format!("Multiple network violations detected ({})", network_violations),
                severity: SeverityLevel::Critical,
                pid: 0,
                timestamp: chrono::Utc::now().timestamp() as u64,
            });
        }
        
        if process_violations >= self.thresholds.max_process_violations {
            return Some(BreachEvent {
                breach_type: BreachType::Process,
                description: format!("Multiple process violations detected ({})", process_violations),
                severity: SeverityLevel::High,
                pid: 0,
                timestamp: chrono::Utc::now().timestamp() as u64,
            });
        }
        
        if events.len() >= self.thresholds.max_suspicious_events {
            return Some(BreachEvent {
                breach_type: BreachType::Other,
                description: format!("Too many suspicious events detected ({})", events.len()),
                severity: SeverityLevel::Medium,
                pid: 0,
                timestamp: chrono::Utc::now().timestamp() as u64,
            });
        }
        
        None
    }
    
    /// Get all breach events
    pub fn get_events(&self) -> Vec<BreachEvent> {
        self.events.lock().unwrap().clone()
    }
    
    /// Clear all breach events
    pub fn clear_events(&self) {
        let mut events = self.events.lock().unwrap();
        events.clear();
    }
}

/// Apply platform-specific security restrictions
#[cfg(target_os = "macos")]
pub fn apply_platform_security(pid: i32, profile: &SecurityLevel) -> Result<()> {
    // macOS implementation
    use std::process::Command;
    
    match profile {
        SecurityLevel::Basic => {
            // Basic security - minimal restrictions
            info!("Applying basic security profile on macOS");
            
            // Use resource limits as the primary mechanism
            apply_resource_limits(pid, 0.9, 1024 * 1024)?;
            
            // Basic file access restrictions via sandbox-exec
            if let Err(e) = apply_sandbox_profile(pid, "basic") {
                warn!("Failed to apply sandbox profile: {}", e);
                // Continue even if we fail - this is just basic security
            }
        },
        SecurityLevel::Standard => {
            // Standard security - moderate restrictions
            info!("Applying standard security profile on macOS");
            
            // Stricter resource limits
            apply_resource_limits(pid, 0.7, 512 * 1024)?;
            
            // Standard file access restrictions
            apply_sandbox_profile(pid, "standard")?;
            
            // Additional process monitoring
            start_process_monitor(pid)?;
        },
        SecurityLevel::Enhanced | SecurityLevel::Maximum => {
            // Enhanced/Maximum security - strict restrictions
            info!("Applying enhanced/maximum security profile on macOS");
            
            // Very strict resource limits
            apply_resource_limits(pid, 0.5, 256 * 1024)?;
            
            // Strict sandboxing
            apply_sandbox_profile(pid, "strict")?;
            
            // Continuous monitoring
            start_process_monitor(pid)?;
            
            // Set CPU priority to low
            set_process_priority(pid, "low")?;
        }
    }
    
    Ok(())
}

/// Apply macOS sandbox-exec profile
#[cfg(target_os = "macos")]
fn apply_sandbox_profile(pid: i32, profile_type: &str) -> Result<()> {
    use std::fs;
    use std::process::Command;
    use std::path::Path;
    
    // Define sandbox profiles based on security level
    let sandbox_profile = match profile_type {
        "basic" => r#"
            (version 1)
            (allow default)
            (deny file-write* (subpath "/System"))
            (deny file-write* (subpath "/usr"))
            (deny file-write* (subpath "/bin"))
            (deny file-write* (subpath "/sbin"))
            (deny file-write* (subpath "/var"))
            (deny file-write* (subpath "/Library"))
        "#,
        "standard" => r#"
            (version 1)
            (allow default)
            (deny file-write*)
            (allow file-write* (subpath "/tmp"))
            (allow file-write* (subpath "/var/tmp"))
            (deny network-outbound)
            (deny system-socket)
            (deny process-fork)
            (deny process-exec)
        "#,
        "strict" => r#"
            (version 1)
            (deny default)
            (allow file-read*)
            (allow file-write* (subpath "/tmp"))
            (deny network*)
            (deny system-socket)
            (deny process-fork)
            (deny process-exec)
            (deny mach*)
            (allow sysctl-read)
            (allow iokit-open (iokit-user-client-class "IOHIDParamUserClient"))
            (allow mach-lookup (global-name "com.apple.system.logger"))
            (allow mach-lookup (global-name "com.apple.system.notification_center"))
        "#,
        _ => return Err(anyhow!("Unknown sandbox profile type: {}", profile_type)),
    };
    
    // Write sandbox profile to temp file
    let profile_path = Path::new("/tmp").join(format!("rusty_sandbox_{}.sb", pid));
    fs::write(&profile_path, sandbox_profile)
        .context("Failed to write sandbox profile")?;
    
    // Apply profile using sandbox-exec
    let output = Command::new("sandbox-exec")
        .args(["-f", profile_path.to_str().unwrap(), "-p", &pid.to_string()])
        .output()
        .context("Failed to execute sandbox-exec")?;
    
    // Clean up temp file
    if let Err(e) = fs::remove_file(&profile_path) {
        warn!("Failed to remove temporary sandbox profile: {}", e);
    }
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("sandbox-exec failed: {}", stderr));
    }
    
    info!("Applied {} sandbox profile to process {}", profile_type, pid);
    Ok(())
}

/// Apply resource limits to a process
#[cfg(target_os = "macos")]
fn apply_resource_limits(pid: i32, cpu_limit: f64, memory_limit_kb: u64) -> Result<()> {
    use std::process::Command;
    
    // Use launchctl limit for resource control
    let output = Command::new("launchctl")
        .args(["limit", "cpu", &format!("{}", (cpu_limit * 100.0) as u32)])
        .output()
        .context("Failed to set CPU limit")?;
    
    if !output.status.success() {
        warn!("Failed to set CPU limit: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    // Set memory limit
    let output = Command::new("launchctl")
        .args(["limit", "rss", &format!("{}", memory_limit_kb)])
        .output()
        .context("Failed to set memory limit")?;
    
    if !output.status.success() {
        warn!("Failed to set memory limit: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    Ok(())
}

/// Start process monitoring
#[cfg(target_os = "macos")]
fn start_process_monitor(pid: i32) -> Result<()> {
    // Here we would start a background thread to monitor the process
    // using macOS-specific APIs
    
    // For now, we'll just register with the process monitoring subsystem
    std::thread::spawn(move || {
        // Simple monitoring loop
        let monitor_interval = std::time::Duration::from_secs(1);
        loop {
            // Check if process still exists
            if !process_exists(pid) {
                break;
            }
            
            // Check resource usage
            if let Ok(usage) = get_process_resource_usage(pid) {
                debug!("Process {}: CPU: {}%, Memory: {} KB", pid, usage.0, usage.1);
            }
            
            std::thread::sleep(monitor_interval);
        }
    });
    
    Ok(())
}

/// Check if process exists
#[cfg(target_os = "macos")]
fn process_exists(pid: i32) -> bool {
    use std::process::Command;
    
    let output = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output();
    
    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// Get process resource usage
#[cfg(target_os = "macos")]
fn get_process_resource_usage(pid: i32) -> Result<(f64, u64)> {
    use std::process::Command;
    
    // Use ps to get CPU and memory usage
    let output = Command::new("ps")
        .args(["-o", "%cpu,rss", "-p", &pid.to_string()])
        .output()
        .context("Failed to execute ps command")?;
    
    if !output.status.success() {
        return Err(anyhow!("ps command failed"));
    }
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = output_str.lines().collect();
    
    if lines.len() < 2 {
        return Err(anyhow!("Unexpected ps output format"));
    }
    
    let stats: Vec<&str> = lines[1].split_whitespace().collect();
    if stats.len() < 2 {
        return Err(anyhow!("Unexpected ps output format"));
    }
    
    let cpu = stats[0].parse::<f64>().context("Failed to parse CPU usage")?;
    let memory = stats[1].parse::<u64>().context("Failed to parse memory usage")?;
    
    Ok((cpu, memory))
}

/// Set process priority
#[cfg(target_os = "macos")]
fn set_process_priority(pid: i32, priority: &str) -> Result<()> {
    use std::process::Command;
    
    // Map priority string to nice value
    let nice_value = match priority {
        "high" => -10,
        "normal" => 0,
        "low" => 10,
        "background" => 20,
        _ => return Err(anyhow!("Unknown priority level: {}", priority)),
    };
    
    // Use renice to set priority
    let output = Command::new("renice")
        .args([&nice_value.to_string(), "-p", &pid.to_string()])
        .output()
        .context("Failed to execute renice command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("renice failed: {}", stderr));
    }
    
    Ok(())
}

/// Language-specific security profile
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LanguageSecurityProfile {
    /// Language identifier
    pub language: String,
    
    /// Allowed filesystem paths for this language
    pub allowed_paths: Vec<String>,
    
    /// Network access policy
    pub network_access: NetworkAccess,
    
    /// Process execution policy
    pub allow_process_execution: bool,
    
    /// Specific system calls to allow
    pub allowed_syscalls: Vec<String>,
    
    /// Maximum memory limit in KB
    pub memory_limit_kb: u64,
    
    /// CPU time limit in seconds
    pub cpu_time_limit_s: u64,
}

impl Default for LanguageSecurityProfile {
    fn default() -> Self {
        Self {
            language: "generic".to_string(),
            allowed_paths: vec!["/tmp".to_string()],
            network_access: NetworkAccess::None,
            allow_process_execution: false,
            allowed_syscalls: vec![],
            memory_limit_kb: 256 * 1024, // 256 MB
            cpu_time_limit_s: 10,
        }
    }
}

impl LanguageSecurityProfile {
    /// Create a profile for a specific language with default settings
    pub fn for_language(language: &str) -> Self {
        match language {
            "python" => Self::python_profile(),
            "javascript" => Self::javascript_profile(),
            "wasm" => Self::wasm_profile(),
            _ => Self::default_with_language(language),
        }
    }
    
    /// Create a default profile with specified language
    pub fn default_with_language(language: &str) -> Self {
        let mut profile = Self::default();
        profile.language = language.to_string();
        profile
    }
    
    /// Create a Python-specific security profile
    pub fn python_profile() -> Self {
        Self {
            language: "python".to_string(),
            allowed_paths: vec![
                "/tmp".to_string(),
                "/usr/lib/python".to_string(),
                "/usr/local/lib/python".to_string(),
            ],
            network_access: NetworkAccess::None,
            allow_process_execution: false,
            allowed_syscalls: vec![
                // Add Python-specific syscalls here
                "read".to_string(),
                "write".to_string(),
                "open".to_string(),
                "close".to_string(),
                "stat".to_string(),
                "fstat".to_string(),
                "lstat".to_string(),
                "poll".to_string(),
                "lseek".to_string(),
                "mmap".to_string(),
                "mprotect".to_string(),
                "munmap".to_string(),
                "brk".to_string(),
                "rt_sigaction".to_string(),
                "rt_sigprocmask".to_string(),
                "rt_sigreturn".to_string(),
                "ioctl".to_string(),
                "pread64".to_string(),
                "pwrite64".to_string(),
                "readv".to_string(),
                "writev".to_string(),
                "access".to_string(),
                "pipe".to_string(),
                "select".to_string(),
                "sched_yield".to_string(),
                "mremap".to_string(),
                "msync".to_string(),
                "mincore".to_string(),
                "madvise".to_string(),
                "shmget".to_string(),
                "shmat".to_string(),
                "shmctl".to_string(),
                "dup".to_string(),
                "dup2".to_string(),
                "pause".to_string(),
                "nanosleep".to_string(),
                "getitimer".to_string(),
                "alarm".to_string(),
                "setitimer".to_string(),
                "getpid".to_string(),
                "sendfile".to_string(),
                "exit".to_string(),
                "uname".to_string(),
                "fcntl".to_string(),
                "flock".to_string(),
                "fsync".to_string(),
                "fdatasync".to_string(),
                "truncate".to_string(),
                "ftruncate".to_string(),
                "getcwd".to_string(),
                "chdir".to_string(),
                "fchdir".to_string(),
                "readlink".to_string(),
                "gettimeofday".to_string(),
                "getrlimit".to_string(),
                "getrusage".to_string(),
                "sysinfo".to_string(),
                "times".to_string(),
                "getuid".to_string(),
                "getgid".to_string(),
                "geteuid".to_string(),
                "getegid".to_string(),
                "getppid".to_string(),
                "getpgrp".to_string(),
                "getdents".to_string(),
                "getdents64".to_string(),
                "socket".to_string(),
                "clock_gettime".to_string(),
                "clock_getres".to_string(),
                "exit_group".to_string(),
                "set_robust_list".to_string(),
                "get_robust_list".to_string(),
                "futex".to_string(),
            ],
            memory_limit_kb: 512 * 1024, // 512 MB
            cpu_time_limit_s: 15,
        }
    }
    
    /// Create a JavaScript-specific security profile
    pub fn javascript_profile() -> Self {
        Self {
            language: "javascript".to_string(),
            allowed_paths: vec![
                "/tmp".to_string(),
                "/usr/lib/node_modules".to_string(),
            ],
            network_access: NetworkAccess::None,
            allow_process_execution: false,
            allowed_syscalls: vec![
                // Add JavaScript-specific syscalls here
                "read".to_string(),
                "write".to_string(),
                "open".to_string(),
                "close".to_string(),
                "stat".to_string(),
                "fstat".to_string(),
                "lstat".to_string(),
                "poll".to_string(),
                "lseek".to_string(),
                "mmap".to_string(),
                "mprotect".to_string(),
                "munmap".to_string(),
                "brk".to_string(),
                "rt_sigaction".to_string(),
                "rt_sigprocmask".to_string(),
                "rt_sigreturn".to_string(),
                "ioctl".to_string(),
                "pread64".to_string(),
                "pwrite64".to_string(),
                "readv".to_string(),
                "writev".to_string(),
                "access".to_string(),
                "pipe".to_string(),
                "select".to_string(),
                "sched_yield".to_string(),
                "mremap".to_string(),
                "msync".to_string(),
                "mincore".to_string(),
                "madvise".to_string(),
                "shmget".to_string(),
                "shmat".to_string(),
                "shmctl".to_string(),
                "dup".to_string(),
                "dup2".to_string(),
                "pause".to_string(),
                "nanosleep".to_string(),
                "getitimer".to_string(),
                "alarm".to_string(),
                "setitimer".to_string(),
                "getpid".to_string(),
                "exit".to_string(),
                "uname".to_string(),
                "fcntl".to_string(),
                "flock".to_string(),
                "fsync".to_string(),
                "fdatasync".to_string(),
                "truncate".to_string(),
                "ftruncate".to_string(),
                "getdents".to_string(),
                "getcwd".to_string(),
                "chdir".to_string(),
                "fchdir".to_string(),
                "readlink".to_string(),
                "gettimeofday".to_string(),
                "getrlimit".to_string(),
                "getrusage".to_string(),
                "sysinfo".to_string(),
                "times".to_string(),
                "getuid".to_string(),
                "getgid".to_string(),
                "geteuid".to_string(),
                "getegid".to_string(),
                "getppid".to_string(),
                "getpgrp".to_string(),
                "socket".to_string(),
                "clock_gettime".to_string(),
                "exit_group".to_string(),
                "epoll_create".to_string(),
                "epoll_ctl".to_string(),
                "epoll_wait".to_string(),
                "set_robust_list".to_string(),
                "futex".to_string(),
            ],
            memory_limit_kb: 384 * 1024, // 384 MB
            cpu_time_limit_s: 12,
        }
    }
    
    /// Create a WebAssembly-specific security profile
    pub fn wasm_profile() -> Self {
        Self {
            language: "wasm".to_string(),
            allowed_paths: vec![
                "/tmp".to_string(),
            ],
            network_access: NetworkAccess::None,
            allow_process_execution: false,
            allowed_syscalls: vec![
                // Add WASM-specific syscalls here
                // WASM is already highly restricted by the runtime
                "read".to_string(),
                "write".to_string(),
                "exit".to_string(),
                "exit_group".to_string(),
                "clock_gettime".to_string(),
                "brk".to_string(),
                "mmap".to_string(),
                "munmap".to_string(),
                "mprotect".to_string(),
                "futex".to_string(),
                "rt_sigreturn".to_string(),
            ],
            memory_limit_kb: 128 * 1024, // 128 MB - WebAssembly is more constrained
            cpu_time_limit_s: 8,
        }
    }
    
    /// Apply this language-specific profile to a sandbox policy
    pub fn apply_to_policy(&self, policy: &mut SandboxPolicy) {
        // Update allowed paths
        policy.allowed_paths.extend(self.allowed_paths.clone());
        
        // Update network access
        policy.enable_network = match self.network_access {
            NetworkAccess::None => false,
            NetworkAccess::Limited(_) | NetworkAccess::Full => true,
        };
        
        // Update process execution
        if let Some(max_processes) = policy.max_processes {
            if !self.allow_process_execution {
                policy.max_processes = Some(1); // Limit to 1 process if process execution not allowed
            }
        }
        
        // Update resource limits
        policy.memory_limit_mb = self.memory_limit_kb / 1024; // Convert KB to MB
        policy.cpu_time_limit_s = self.cpu_time_limit_s;
        
        // Custom syscalls will be handled by the seccomp profile setup
    }
    
    /// Get the allowed syscalls for this language profile
    pub fn get_allowed_syscalls(&self) -> Vec<String> {
        self.allowed_syscalls.clone()
    }
}

/// Register language-specific security profiles in the configuration
pub fn register_language_profiles() -> Result<()> {
    // This would normally load from config files
    // For now, we'll just register the built-in profiles
    
    let profiles = [
        LanguageSecurityProfile::python_profile(),
        LanguageSecurityProfile::javascript_profile(),
        LanguageSecurityProfile::wasm_profile(),
    ];
    
    // Store these profiles in a global registry or config system
    // For now, just log that they're registered
    for profile in &profiles {
        info!("Registered security profile for {}", profile.language);
    }
    
    Ok(())
}

/// Get a language-specific security profile
pub fn get_language_profile(language: &str) -> LanguageSecurityProfile {
    // In a production system, this would look up from a registry
    // For now, we'll just create them on demand
    LanguageSecurityProfile::for_language(language)
} 