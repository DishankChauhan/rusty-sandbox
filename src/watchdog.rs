use anyhow::{anyhow, Result, Context};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};
use log::{error, info, warn};
use nix::{sys::signal, unistd::Pid};

#[cfg(all(target_os = "linux", feature = "linux"))]
use procfs;

#[cfg(target_os = "linux")]
use crate::cgroups::CgroupManager;
use crate::resources::ResourceMonitor;

/// Represents the current state of the sandbox
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SandboxState {
    Running,
    Terminated,
    Breached,
    TimedOut,
    ResourceExceeded,
}

/// Watchdog configuration parameters
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    /// How frequently to check for breaches (in milliseconds)
    pub check_interval_ms: u64,
    /// Process namespace verification enabled
    pub verify_namespaces: bool,
    /// Process hierarchy verification enabled
    pub verify_process_hierarchy: bool,
    /// Maximum time to run before force termination (in seconds)
    pub max_runtime_sec: u64,
    /// Resource threshold percentage (0-100) for early warning
    pub resource_threshold: u8,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            check_interval_ms: 500,
            verify_namespaces: true,
            verify_process_hierarchy: true,
            max_runtime_sec: 300, // 5 minutes default maximum runtime
            resource_threshold: 80, // 80% threshold for early warning
        }
    }
}

/// Watchdog guards against sandbox escapes and ensures processes terminate
pub struct Watchdog {
    config: WatchdogConfig,
    pid: Pid,
    child_pids: Arc<Mutex<Vec<Pid>>>,
    state: Arc<Mutex<SandboxState>>,
    running: Arc<AtomicBool>,
    start_time: Instant,
    resource_monitor: Arc<ResourceMonitor>,
    #[cfg(target_os = "linux")]
    cgroup_manager: Option<Arc<CgroupManager>>,
}

impl Watchdog {
    /// Create a new watchdog for the given PID
    #[cfg(target_os = "linux")]
    pub fn new(
        pid: Pid, 
        config: WatchdogConfig, 
        resource_monitor: Arc<ResourceMonitor>,
        cgroup_manager: Option<Arc<CgroupManager>>,
    ) -> Self {
        Self {
            config,
            pid,
            child_pids: Arc::new(Mutex::new(Vec::new())),
            state: Arc::new(Mutex::new(SandboxState::Running)),
            running: Arc::new(AtomicBool::new(false)),
            start_time: Instant::now(),
            resource_monitor,
            cgroup_manager,
        }
    }

    /// Create a new watchdog for non-Linux platforms
    #[cfg(not(target_os = "linux"))]
    pub fn new(
        pid: Pid, 
        config: WatchdogConfig, 
        resource_monitor: Arc<ResourceMonitor>,
    ) -> Self {
        Self {
            config,
            pid,
            child_pids: Arc::new(Mutex::new(Vec::new())),
            state: Arc::new(Mutex::new(SandboxState::Running)),
            running: Arc::new(AtomicBool::new(false)),
            start_time: Instant::now(),
            resource_monitor,
        }
    }

    /// Start the watchdog in a separate thread
    pub fn start(&mut self) -> Result<()> {
        // Check if already running
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Watchdog already running"));
        }

        self.running.store(true, Ordering::SeqCst);
        
        // Clone references for thread
        let running = self.running.clone();
        let config = self.config.clone();
        let pid = self.pid;
        let state = self.state.clone();
        let child_pids = self.child_pids.clone();
        let start_time = self.start_time;
        let resource_monitor = self.resource_monitor.clone();
        
        #[cfg(target_os = "linux")]
        let cgroup_manager = self.cgroup_manager.clone();

        // Spawn watchdog thread
        thread::spawn(move || {
            info!("Watchdog started for PID {}", pid);
            
            while running.load(Ordering::SeqCst) {
                // Check runtime limit
                let runtime = start_time.elapsed();
                if runtime.as_secs() > config.max_runtime_sec {
                    error!("Sandbox exceeded maximum runtime of {} seconds", config.max_runtime_sec);
                    *state.lock().unwrap() = SandboxState::TimedOut;
                    Self::terminate_process_tree(pid, &child_pids);
                    break;
                }

                // Platform specific checks
                #[cfg(target_os = "linux")]
                if let Err(err) = Self::check_linux_sandbox_integrity(
                    pid, 
                    &config,
                    &state,
                    &child_pids,
                    &cgroup_manager,
                ) {
                    error!("Sandbox integrity check failed: {}", err);
                    *state.lock().unwrap() = SandboxState::Breached;
                    Self::terminate_process_tree(pid, &child_pids);
                    break;
                }

                // Check resource usage against thresholds
                if let Err(err) = Self::check_resource_usage(
                    &resource_monitor,
                    &config,
                    &state,
                    pid,
                    &child_pids,
                ) {
                    error!("Resource check failed: {}", err);
                    *state.lock().unwrap() = SandboxState::ResourceExceeded;
                    Self::terminate_process_tree(pid, &child_pids);
                    break;
                }

                // Update child PIDs list
                if let Err(err) = Self::update_child_processes(pid, &child_pids) {
                    warn!("Failed to update child process list: {}", err);
                }

                // Check if process is still alive
                if !Self::is_process_alive(pid) {
                    info!("Sandbox process {} has terminated", pid);
                    *state.lock().unwrap() = SandboxState::Terminated;
                    break;
                }

                // Sleep for the configured interval
                thread::sleep(Duration::from_millis(config.check_interval_ms));
            }

            info!("Watchdog for PID {} has stopped", pid);
            running.store(false, Ordering::SeqCst);
        });

        Ok(())
    }

    /// Stop the watchdog
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Watchdog stop signal sent");
    }

    /// Get current sandbox state
    pub fn state(&self) -> SandboxState {
        *self.state.lock().unwrap()
    }

    /// Check resource usage against thresholds
    fn check_resource_usage(
        resource_monitor: &ResourceMonitor,
        config: &WatchdogConfig,
        state: &Arc<Mutex<SandboxState>>,
        pid: Pid,
        child_pids: &Arc<Mutex<Vec<Pid>>>,
    ) -> Result<()> {
        // Get latest resource metrics
        let metrics = resource_monitor.get_latest_metrics();
        
        // Check for abnormal resource usage
        if let Some(cpu) = metrics.cpu_usage {
            if cpu > config.resource_threshold as f64 {
                warn!("Sandbox CPU usage exceeds threshold: {:.1}%", cpu);
                // Just warn, don't terminate yet
            }
        }
        
        if let Some(mem) = metrics.memory_usage_percent {
            if mem > config.resource_threshold as f64 {
                warn!("Sandbox memory usage exceeds threshold: {:.1}%", mem);
                // Just warn, don't terminate yet
            }
        }
        
        // Check if resources were completely exceeded (according to metrics)
        if metrics.limits_exceeded {
            error!("Sandbox resource limits exceeded, terminating");
            *state.lock().unwrap() = SandboxState::ResourceExceeded;
            return Ok(());
        }
        
        Ok(())
    }

    /// Terminate the process and all its children
    fn terminate_process_tree(pid: Pid, child_pids: &Arc<Mutex<Vec<Pid>>>) {
        // First try to terminate nicely with SIGTERM
        let _ = signal::kill(pid, signal::Signal::SIGTERM);
        
        // Also terminate all children
        for child_pid in child_pids.lock().unwrap().iter() {
            let _ = signal::kill(*child_pid, signal::Signal::SIGTERM);
        }
        
        // Give processes time to shut down gracefully
        thread::sleep(Duration::from_millis(500));
        
        // Force kill any remaining processes
        let _ = signal::kill(pid, signal::Signal::SIGKILL);
        for child_pid in child_pids.lock().unwrap().iter() {
            let _ = signal::kill(*child_pid, signal::Signal::SIGKILL);
        }
        
        info!("Terminated process tree for PID {}", pid);
    }

    /// Update the list of child processes
    fn update_child_processes(pid: Pid, child_pids: &Arc<Mutex<Vec<Pid>>>) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let mut children = Vec::new();
            Self::get_all_children(pid, &mut children)?;
            
            // Update the shared list
            let mut pids = child_pids.lock().unwrap();
            *pids = children;
            
            Ok(())
        }
        
        #[cfg(target_os = "macos")]
        {
            // macOS implementation for process hierarchy detection
            let mut children = Vec::new();
            Self::get_macos_process_children(pid, &mut children)?;
            
            // Update the shared list
            let mut pids = child_pids.lock().unwrap();
            *pids = children;
            
            Ok(())
        }
        
        #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
        {
            // On other platforms, implement a basic version using available system APIs
            warn!("Child process tracking is limited on this platform");
            Ok(())
        }
    }

    /// Check if process is still alive
    fn is_process_alive(pid: Pid) -> bool {
        signal::kill(pid, None).is_ok()
    }

    #[cfg(target_os = "linux")]
    fn get_all_children(pid: Pid, children: &mut Vec<Pid>) -> Result<()> {
        // Use procfs to find direct children
        let processes = procfs::process::all_processes()?;
        
        for process in processes {
            if let Ok(process) = process {
                if let Ok(stat) = process.stat() {
                    if stat.ppid == pid.as_raw() as i32 {
                        let child_pid = Pid::from_raw(stat.pid);
                        children.push(child_pid);
                        
                        // Recursively get grandchildren
                        Self::get_all_children(child_pid, children)?;
                    }
                }
            }
        }
        
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn check_linux_sandbox_integrity(
        pid: Pid,
        config: &WatchdogConfig,
        state: &Arc<Mutex<SandboxState>>,
        child_pids: &Arc<Mutex<Vec<Pid>>>,
        cgroup_manager: &Option<Arc<CgroupManager>>,
    ) -> Result<()> {
        // Check namespace isolation if configured
        if config.verify_namespaces {
            Self::verify_namespace_isolation(pid)?;
        }
        
        // Check process hierarchy if configured
        if config.verify_process_hierarchy {
            Self::verify_process_hierarchy(pid, child_pids)?;
        }
        
        // Check cgroup containment if available
        if let Some(cgroup_mgr) = cgroup_manager {
            Self::verify_cgroup_containment(pid, child_pids, cgroup_mgr)?;
        }
        
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn verify_namespace_isolation(pid: Pid) -> Result<()> {
        let proc_path = format!("/proc/{}/ns", pid.as_raw());
        
        // Get root namespaces for comparison
        let root_namespaces = Self::get_namespaces(Pid::from_raw(1))?;
        
        // Get sandboxed process namespaces
        let process_namespaces = Self::get_namespaces(pid)?;
        
        // Check for namespace differences that should exist in a proper sandbox
        // At minimum, PID and mount namespaces should be different
        if process_namespaces.get("pid") == root_namespaces.get("pid") {
            return Err(anyhow!("PID namespace isolation breach detected"));
        }
        
        if process_namespaces.get("mnt") == root_namespaces.get("mnt") {
            return Err(anyhow!("Mount namespace isolation breach detected"));
        }
        
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn get_namespaces(pid: Pid) -> Result<std::collections::HashMap<String, String>> {
        use std::collections::HashMap;
        use std::fs;
        use std::path::Path;
        
        let mut namespaces = HashMap::new();
        let ns_path = Path::new("/proc").join(pid.as_raw().to_string()).join("ns");
        
        if !ns_path.exists() {
            return Err(anyhow!("Process namespace information not available"));
        }
        
        for entry in fs::read_dir(ns_path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            
            // Read the symlink target which contains the namespace identifier
            if let Ok(target) = fs::read_link(entry.path()) {
                let ns_id = target.to_string_lossy().to_string();
                namespaces.insert(name, ns_id);
            }
        }
        
        Ok(namespaces)
    }

    #[cfg(target_os = "linux")]
    fn verify_process_hierarchy(pid: Pid, child_pids: &Arc<Mutex<Vec<Pid>>>) -> Result<()> {
        // Get all processes in the system
        let processes = procfs::process::all_processes()?;
        
        // Build a map of our known child PIDs for quick lookup
        let our_pids = {
            let mut set = std::collections::HashSet::new();
            set.insert(pid.as_raw() as i32);
            
            for child_pid in child_pids.lock().unwrap().iter() {
                set.insert(child_pid.as_raw() as i32);
            }
            
            set
        };
        
        // Look for descendants of our PID that aren't in our tracking list
        for process in processes {
            if let Ok(process) = process {
                if let Ok(stat) = process.stat() {
                    // Skip processes we already know about
                    if our_pids.contains(&stat.pid) {
                        continue;
                    }
                    
                    // Check if this process has one of our PIDs as a parent
                    if our_pids.contains(&stat.ppid) {
                        // Found a child process not in our list - potential escape
                        return Err(anyhow!(
                            "Process hierarchy breach detected: PID {} (parent: {}) not tracked",
                            stat.pid, stat.ppid
                        ));
                    }
                }
            }
        }
        
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn verify_cgroup_containment(
        pid: Pid, 
        child_pids: &Arc<Mutex<Vec<Pid>>>,
        cgroup_manager: &Arc<CgroupManager>,
    ) -> Result<()> {
        // Verify main process is in our cgroup
        if !cgroup_manager.is_process_in_cgroup(pid.as_raw() as u32)? {
            return Err(anyhow!("Main process {} not in controlled cgroup", pid));
        }
        
        // Verify all children are in our cgroup
        for child_pid in child_pids.lock().unwrap().iter() {
            if !cgroup_manager.is_process_in_cgroup(child_pid.as_raw() as u32)? {
                return Err(anyhow!("Child process {} not in controlled cgroup", child_pid));
            }
        }
        
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn get_macos_process_children(pid: Pid, children: &mut Vec<Pid>) -> Result<()> {
        use std::process::Command;
        use std::str;
        
        // macOS pgrep can find process by PPID
        let output = Command::new("pgrep")
            .args(&["-P", &pid.as_raw().to_string()])
            .output()
            .map_err(|e| anyhow!("Failed to execute pgrep: {}", e))?;
            
        if output.status.success() {
            // Parse the output which contains one PID per line
            if let Ok(stdout) = str::from_utf8(&output.stdout) {
                for line in stdout.lines() {
                    if let Ok(child_pid) = line.trim().parse::<i32>() {
                        let child_pid = Pid::from_raw(child_pid);
                        children.push(child_pid);
                        
                        // Recursively get grandchildren
                        let _ = Self::get_macos_process_children(child_pid, children);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "macos")]
    fn check_macos_sandbox_integrity(
        pid: Pid,
        config: &WatchdogConfig,
        state: &Arc<Mutex<SandboxState>>,
        child_pids: &Arc<Mutex<Vec<Pid>>>,
    ) -> Result<()> {
        use std::process::Command;
        
        // Check for suspicious process activity using macOS tools
        
        // 1. Check if process is using more file descriptors than expected
        // Use lsof to count open files
        let output = Command::new("lsof")
            .args(&["-p", &pid.as_raw().to_string()])
            .output();
            
        if let Ok(output) = output {
            if output.status.success() {
                // Count number of lines (each is a file descriptor)
                // Skip the header line
                let fd_count = output.stdout.iter().filter(|&&b| b == b'\n').count();
                if fd_count > 1000 { // Arbitrary limit, adjust based on your security needs
                    return Err(anyhow!("Process has suspiciously high number of open files: {}", fd_count));
                }
            }
        }
        
        // 2. Check process permissions with csrutil 
        // (System Integrity Protection status)
        if config.verify_process_hierarchy {
            let output = Command::new("ps")
                .args(&["-p", &pid.as_raw().to_string(), "-o", "uid"])
                .output();
                
            if let Ok(output) = output {
                if output.status.success() {
                    if let Ok(stdout) = std::str::from_utf8(&output.stdout) {
                        // Check if process is running as root (UID 0)
                        // Skip header line
                        for line in stdout.lines().skip(1) {
                            if line.trim() == "0" {
                                return Err(anyhow!("Security breach: Process is running as root"));
                            }
                        }
                    }
                }
            }
        }
        
        // 3. Check for suspicious ports being opened
        // This would detect if the sandbox is trying to open network connections
        // when it shouldn't be allowed to
        let output = Command::new("lsof")
            .args(&["-p", &pid.as_raw().to_string(), "-i", "-n"])
            .output();
            
        if let Ok(output) = output {
            if output.status.success() {
                if !output.stdout.is_empty() {
                    // Process has network connections
                    if let Ok(stdout) = std::str::from_utf8(&output.stdout) {
                        info!("Network activity detected for sandboxed process: {}", stdout);
                        // This could be a policy violation depending on configuration
                        // For now, just log it, but you could return an error if network
                        // access should be forbidden
                    }
                }
            }
        }
        
        Ok(())
    }

    // Add a platform-agnostic function to check sandbox integrity
    fn check_sandbox_integrity(
        pid: Pid,
        config: &WatchdogConfig,
        state: &Arc<Mutex<SandboxState>>,
        child_pids: &Arc<Mutex<Vec<Pid>>>,
        #[cfg(target_os = "linux")] cgroup_manager: &Option<Arc<CgroupManager>>,
    ) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            Self::check_linux_sandbox_integrity(
                pid,
                config,
                state,
                child_pids,
                cgroup_manager,
            )
        }
        
        #[cfg(target_os = "macos")]
        {
            Self::check_macos_sandbox_integrity(
                pid,
                config,
                state,
                child_pids,
            )
        }
        
        #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
        {
            // Basic checks for other platforms
            Ok(())
        }
    }

    /// Check for sandbox breaches related to unauthorized processes
    pub fn detect_unauthorized_processes(pid: i32, allowed_cmds: &[String]) -> Result<bool> {
        let children = Self::get_process_children(pid)?;
        
        for child_pid in children {
            let child_cmd = Self::get_process_command(child_pid)?;
            
            // Check if this is an authorized command
            let authorized = allowed_cmds.iter()
                .any(|cmd| child_cmd.contains(cmd));
                
            if !authorized {
                warn!("Unauthorized process detected: {} ({})", child_pid, child_cmd);
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    /// Get child processes of the given PID
    fn get_process_children(pid: i32) -> Result<Vec<i32>> {
        use std::process::Command;
        
        // Run pgrep to find children
        let output = Command::new("pgrep")
            .args(["-P", &pid.to_string()])
            .output()
            .context("Failed to execute pgrep command")?;
        
        if !output.status.success() && !output.stdout.is_empty() {
            // pgrep returns non-zero if no processes match, which is fine
            return Ok(Vec::new());
        }
        
        // Parse the output to get PIDs
        let output_str = String::from_utf8_lossy(&output.stdout);
        let pids: Vec<i32> = output_str
            .lines()
            .filter_map(|line| line.trim().parse::<i32>().ok())
            .collect();
        
        Ok(pids)
    }

    /// Get the command line of a process
    fn get_process_command(pid: i32) -> Result<String> {
        use std::process::Command;
        
        // Use ps to get the command
        let output = Command::new("ps")
            .args(["-o", "command=", "-p", &pid.to_string()])
            .output()
            .context("Failed to execute ps command")?;
            
        if !output.status.success() {
            return Err(anyhow!("Failed to get command for process {}", pid));
        }
        
        let cmd = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(cmd)
    }
} 