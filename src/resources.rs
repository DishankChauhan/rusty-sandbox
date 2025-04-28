use anyhow::{anyhow, Result};
use log::{debug, warn, error, info};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{ProcessExt, System, SystemExt};

#[cfg(target_os = "linux")]
use procfs::process::{Process, ProcState};

/// Configuration for resource limits within the sandbox
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum CPU usage percentage (0-100)
    pub max_cpu_percent: f64,
    /// Maximum memory usage in bytes
    pub max_memory_bytes: u64,
    /// Maximum memory usage as percentage of system memory
    pub max_memory_percent: f64,
    /// Maximum number of threads
    pub max_threads: Option<u32>,
    /// Maximum number of open file descriptors
    pub max_open_files: Option<u32>,
    /// Maximum disk usage in bytes
    pub max_disk_bytes: Option<u64>,
    /// Maximum network bandwidth in bytes per second
    pub max_network_bps: Option<u64>,
    /// CPU time slice in milliseconds (for limiting CPU bursts)
    pub cpu_time_slice_ms: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        ResourceLimits {
            max_cpu_percent: 80.0,
            max_memory_bytes: 1024 * 1024 * 1024, // 1GB
            max_memory_percent: 30.0,
            max_threads: Some(100),
            max_open_files: Some(1024),
            max_disk_bytes: Some(1024 * 1024 * 1024), // 1GB
            max_network_bps: Some(1024 * 1024 * 10), // 10 MB/s
            cpu_time_slice_ms: Some(100),
        }
    }
}

/// Current resource usage metrics for a sandboxed process
#[derive(Debug, Clone)]
pub struct ResourceMetrics {
    /// CPU usage as a percentage (0-100)
    pub cpu_usage: Option<f64>,
    /// Memory usage in bytes
    pub memory_usage_bytes: Option<u64>,
    /// Memory usage as a percentage of system memory
    pub memory_usage_percent: Option<f64>,
    /// Number of threads
    pub thread_count: Option<u32>,
    /// Number of open file descriptors
    pub open_files: Option<u32>,
    /// Disk usage in bytes
    pub disk_usage_bytes: Option<u64>,
    /// Network usage in bytes per second
    pub network_usage_bps: Option<u64>,
    /// Whether any resource limits have been exceeded
    pub limits_exceeded: bool,
    /// Map of which limits were exceeded
    pub exceeded_limits: HashMap<String, String>,
    /// Timestamp when metrics were collected
    pub timestamp: u64,
}

impl Default for ResourceMetrics {
    fn default() -> Self {
        ResourceMetrics {
            cpu_usage: None,
            memory_usage_bytes: None,
            memory_usage_percent: None,
            thread_count: None,
            open_files: None,
            disk_usage_bytes: None,
            network_usage_bps: None,
            limits_exceeded: false,
            exceeded_limits: HashMap::new(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }
}

/// Resource monitor for tracking and enforcing resource limits
pub struct ResourceMonitor {
    /// Process ID to monitor
    pid: u32,
    /// Resource limits configuration
    limits: ResourceLimits,
    /// System info collection
    system: System,
    /// Historical metrics for calculating rates
    historical_metrics: HashMap<String, Vec<(Instant, f64)>>,
    /// Whether monitoring is active
    active: Arc<Mutex<bool>>,
    /// Latest metrics from monitoring
    latest_metrics: Arc<Mutex<ResourceMetrics>>,
    /// Optional callback when limits are exceeded
    on_limit_exceeded: Option<Box<dyn Fn(&ResourceMetrics) + Send + Sync>>,
}

impl ResourceMonitor {
    /// Create a new resource monitor for the given process
    pub fn new(pid: u32, limits: ResourceLimits) -> Self {
        let mut system = System::new();
        system.refresh_all();
        
        ResourceMonitor {
            pid,
            limits,
            system,
            historical_metrics: HashMap::new(),
            active: Arc::new(Mutex::new(false)),
            latest_metrics: Arc::new(Mutex::new(ResourceMetrics::default())),
            on_limit_exceeded: None,
        }
    }
    
    /// Set a callback function to be called when resource limits are exceeded
    pub fn on_limit_exceeded<F>(&mut self, callback: F)
    where
        F: Fn(&ResourceMetrics) + Send + Sync + 'static,
    {
        self.on_limit_exceeded = Some(Box::new(callback));
    }
    
    /// Start monitoring resources in a background thread
    pub fn start_monitoring(&mut self, interval_ms: u64) -> Result<()> {
        let pid = self.pid;
        let limits = self.limits.clone();
        let active = Arc::clone(&self.active);
        let latest_metrics = Arc::clone(&self.latest_metrics);
        let on_limit_exceeded = self.on_limit_exceeded.take();
        
        // Set the active flag
        {
            let mut active_guard = active.lock().unwrap();
            *active_guard = true;
        }
        
        thread::spawn(move || {
            let mut system = System::new();
            let mut historical_metrics: HashMap<String, Vec<(Instant, f64)>> = HashMap::new();
            
            #[cfg(target_os = "linux")]
            let mut procfs_process = Process::new(pid as i32).ok();
            
            while *active.lock().unwrap() {
                // Refresh system data
                system.refresh_all();
                
                // Get the process and check if it still exists
                if let Some(process) = system.process(sysinfo::Pid::from(pid as usize)) {
                    // Create a new metrics object
                    let mut metrics = ResourceMetrics::default();
                    metrics.timestamp = chrono::Utc::now().timestamp() as u64;
                    
                    // Collect CPU usage
                    let cpu_usage = process.cpu_usage() as f64;
                    metrics.cpu_usage = Some(cpu_usage);
                    
                    // Record historical CPU usage for rate calculations
                    let now = Instant::now();
                    
                    // Store current value with timestamp
                    let cpu_history = historical_metrics
                        .entry("cpu".to_string())
                        .or_insert_with(Vec::new);
                    cpu_history.push((now, cpu_usage));
                    
                    // Cleanup old history (keep last 10 seconds)
                    cpu_history.retain(|(t, _)| now.duration_since(*t) < Duration::from_secs(10));
                    
                    // Collect memory usage
                    let memory_bytes = process.memory() as u64;
                    metrics.memory_usage_bytes = Some(memory_bytes);
                    
                    // Calculate memory percentage
                    let total_memory = system.total_memory();
                    if total_memory > 0 {
                        let memory_percent = (memory_bytes as f64 / total_memory as f64) * 100.0;
                        metrics.memory_usage_percent = Some(memory_percent);
                    }
                    
                    // Thread count
                    // Different ways to get thread count depending on system/version
                    #[cfg(not(target_os = "macos"))]
                    {
                        // For Linux and others
                        metrics.thread_count = Some(process.num_threads() as u32);
                    }
                    
                    #[cfg(target_os = "macos")]
                    {
                        // On macOS, count the number of threads using ps command
                        metrics.thread_count = Some(1); // Default to at least 1 thread
                        
                        if let Ok(output) = std::process::Command::new("ps")
                            .args(&["-M", &pid.to_string()])
                            .output() 
                        {
                            if output.status.success() {
                                // Count the lines in output, subtract 1 for header
                                let thread_count = String::from_utf8_lossy(&output.stdout)
                                    .lines()
                                    .count()
                                    .saturating_sub(1);
                                metrics.thread_count = Some(thread_count as u32);
                            }
                        }
                    }
                    
                    // Linux-specific metrics
                    #[cfg(target_os = "linux")]
                    {
                        // Use procfs to get open file count
                        if let Some(ref mut proc) = procfs_process {
                            if let Ok(fds) = proc.fd() {
                                metrics.open_files = Some(fds.len() as u32);
                            }
                            
                            // Refresh process data
                            if let Err(e) = proc.update() {
                                error!("Failed to update procfs data: {}", e);
                                // Try to recreate the process handle
                                procfs_process = Process::new(pid as i32).ok();
                            }
                        }
                    }
                    
                    // Check if any limits are exceeded
                    metrics.exceeded_limits = HashMap::new();
                    
                    // Check CPU limit
                    if let Some(cpu) = metrics.cpu_usage {
                        if cpu > limits.max_cpu_percent {
                            metrics.limits_exceeded = true;
                            metrics.exceeded_limits.insert(
                                "cpu".to_string(),
                                format!("{:.1}% > {:.1}%", cpu, limits.max_cpu_percent)
                            );
                        }
                    }
                    
                    // Check memory limit (bytes)
                    if let Some(memory) = metrics.memory_usage_bytes {
                        if memory > limits.max_memory_bytes {
                            metrics.limits_exceeded = true;
                            metrics.exceeded_limits.insert(
                                "memory_bytes".to_string(),
                                format!("{} > {}", memory, limits.max_memory_bytes)
                            );
                        }
                    }
                    
                    // Check memory limit (percent)
                    if let Some(memory_percent) = metrics.memory_usage_percent {
                        if memory_percent > limits.max_memory_percent {
                            metrics.limits_exceeded = true;
                            metrics.exceeded_limits.insert(
                                "memory_percent".to_string(),
                                format!("{:.1}% > {:.1}%", memory_percent, limits.max_memory_percent)
                            );
                        }
                    }
                    
                    // Check thread limit
                    if let (Some(threads), Some(max_threads)) = (metrics.thread_count, limits.max_threads) {
                        if threads > max_threads {
                            metrics.limits_exceeded = true;
                            metrics.exceeded_limits.insert(
                                "threads".to_string(),
                                format!("{} > {}", threads, max_threads)
                            );
                        }
                    }
                    
                    // Check open files limit
                    if let (Some(open_files), Some(max_open_files)) = (metrics.open_files, limits.max_open_files) {
                        if open_files > max_open_files {
                            metrics.limits_exceeded = true;
                            metrics.exceeded_limits.insert(
                                "open_files".to_string(),
                                format!("{} > {}", open_files, max_open_files)
                            );
                        }
                    }
                    
                    // If limits are exceeded, call the callback if set
                    if metrics.limits_exceeded {
                        if let Some(ref callback) = on_limit_exceeded {
                            callback(&metrics);
                        }
                    }
                    
                    // Update latest metrics
                    {
                        let mut latest = latest_metrics.lock().unwrap();
                        *latest = metrics;
                    }
                } else {
                    debug!("Process {} no longer exists, stopping resource monitor", pid);
                    *active.lock().unwrap() = false;
                    break;
                }
                
                // Wait for next check
                thread::sleep(Duration::from_millis(interval_ms));
            }
        });
        
        Ok(())
    }
    
    /// Stop the resource monitoring thread
    pub fn stop(&mut self) {
        let mut active = self.active.lock().unwrap();
        *active = false;
    }
    
    /// Get the latest resource metrics
    pub fn get_latest_metrics(&self) -> ResourceMetrics {
        self.latest_metrics.lock().unwrap().clone()
    }
    
    /// Check if limits are currently being exceeded
    pub fn is_exceeding_limits(&self) -> bool {
        self.latest_metrics.lock().unwrap().limits_exceeded
    }
    
    /// Apply resource limits (platform-specific)
    pub fn apply_limits(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.apply_cgroup_limits()?;
        }
        
        #[cfg(target_os = "macos")]
        {
            self.apply_macos_limits()?;
        }
        
        #[cfg(target_os = "windows")]
        {
            warn!("Resource limits application on Windows is limited to monitoring only");
            // On Windows we'll rely on monitoring and termination rather than OS enforcement
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "macos")]
    /// Apply resource limits using macOS-specific APIs
    fn apply_macos_limits(&self) -> Result<()> {
        use std::process::Command;
        
        // On macOS, we'll use a combination of:
        // 1. launchd job priority adjustment for CPU limiting
        // 2. Process resource limits using setrlimit equivalents
        // 3. Memory limits using jemalloc hooks if available
        
        // Adjust process priority using nice
        if self.limits.max_cpu_percent < 50.0 {
            // Lower priority for processes requesting less than 50% CPU
            let nice_val = 10; // Higher nice value means lower priority
            let result = Command::new("renice")
                .args(&["-n", &nice_val.to_string(), "-p", &self.pid.to_string()])
                .output();
                
            if let Err(e) = result {
                warn!("Failed to set process priority with renice: {}", e);
            }
        }
        
        // Use process_vm_limit if installed (third-party tool)
        if let Some(max_memory) = Some(self.limits.max_memory_bytes) {
            let memory_mb = max_memory / (1024 * 1024);
            // Check if process_vm_limit is installed
            let vm_limit_check = Command::new("which")
                .arg("process_vm_limit")
                .output();
                
            match vm_limit_check {
                Ok(output) if !output.stdout.is_empty() => {
                    // The tool is installed, use it
                    let result = Command::new("process_vm_limit")
                        .args(&["-p", &self.pid.to_string(), "-l", &memory_mb.to_string()])
                        .output();
                        
                    if let Err(e) = result {
                        warn!("Failed to set memory limit with process_vm_limit: {}", e);
                    } else {
                        info!("Applied memory limit of {} MB to process {}", memory_mb, self.pid);
                    }
                },
                _ => {
                    warn!("process_vm_limit tool not found for macOS memory limiting");
                    warn!("Memory limits will be enforced through monitoring and termination");
                }
            }
        }
        
        // Use taskpolicy to prevent App Nap
        // This ensures consistent CPU allocation for accurate monitoring
        let _ = Command::new("taskpolicy")
            .args(&["-b", &self.pid.to_string()])
            .output();
        
        info!("Applied macOS resource constraints to process {}", self.pid);
        info!("Full enforcement relies on monitoring and termination");
        
        Ok(())
    }
    
    #[cfg(target_os = "linux")]
    /// Apply resource limits using cgroups (Linux-only)
    fn apply_cgroup_limits(&self) -> Result<()> {
        use std::fs::File;
        use std::io::Write;
        use std::path::Path;
        
        // Check if the cgroup v2 is available
        let cgroup_path = Path::new("/sys/fs/cgroup");
        if !cgroup_path.exists() {
            return Err(anyhow!("Cgroup filesystem not mounted"));
        }
        
        // Create a cgroup for this sandbox if it doesn't exist
        let sandbox_cgroup = cgroup_path.join(format!("rusty-sandbox-{}", self.pid));
        if !sandbox_cgroup.exists() {
            std::fs::create_dir_all(&sandbox_cgroup)
                .map_err(|e| anyhow!("Failed to create cgroup directory: {}", e))?;
        }
        
        // Add the process to the cgroup
        let mut procs_file = File::create(sandbox_cgroup.join("cgroup.procs"))
            .map_err(|e| anyhow!("Failed to open cgroup.procs: {}", e))?;
        write!(procs_file, "{}", self.pid)
            .map_err(|e| anyhow!("Failed to write to cgroup.procs: {}", e))?;
        
        // Set CPU limit
        if let Some(cpu_slice) = self.limits.cpu_time_slice_ms {
            let cpu_max_file = sandbox_cgroup.join("cpu.max");
            if cpu_max_file.exists() {
                let cpu_quota = cpu_slice as u64 * 1000; // Convert to microseconds
                let mut cpu_max = File::create(cpu_max_file)
                    .map_err(|e| anyhow!("Failed to open cpu.max: {}", e))?;
                write!(cpu_max, "{} 100000", cpu_quota)
                    .map_err(|e| anyhow!("Failed to write to cpu.max: {}", e))?;
            }
        }
        
        // Set memory limit
        let memory_max_file = sandbox_cgroup.join("memory.max");
        if memory_max_file.exists() {
            let mut memory_max = File::create(memory_max_file)
                .map_err(|e| anyhow!("Failed to open memory.max: {}", e))?;
            write!(memory_max, "{}", self.limits.max_memory_bytes)
                .map_err(|e| anyhow!("Failed to write to memory.max: {}", e))?;
        }
        
        // Set OOM behavior - prefer this process for OOM killing
        let memory_oom_file = sandbox_cgroup.join("memory.oom.group");
        if memory_oom_file.exists() {
            let mut oom_file = File::create(memory_oom_file)
                .map_err(|e| anyhow!("Failed to open memory.oom.group: {}", e))?;
            write!(oom_file, "1")
                .map_err(|e| anyhow!("Failed to write to memory.oom.group: {}", e))?;
        }
        
        Ok(())
    }
    
    /// Clean up any resources used by the monitor
    pub fn cleanup(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            // Clean up cgroup
            let cgroup_path = Path::new("/sys/fs/cgroup")
                .join(format!("rusty-sandbox-{}", self.pid));
            
            if cgroup_path.exists() {
                // Move processes to the parent cgroup first
                let procs_path = cgroup_path.join("cgroup.procs");
                if procs_path.exists() {
                    // Read all PIDs in this cgroup
                    if let Ok(procs_content) = std::fs::read_to_string(&procs_path) {
                        // Parent cgroup procs file
                        if let Ok(mut parent_procs) = File::create("/sys/fs/cgroup/cgroup.procs") {
                            // Move each process to the parent
                            for pid in procs_content.lines() {
                                let _ = write!(parent_procs, "{}", pid);
                            }
                        }
                    }
                }
                
                // Remove the cgroup directory
                let _ = std::fs::remove_dir(&cgroup_path);
            }
        }
        
        Ok(())
    }
}

/// Get memory usage for a process on macOS
#[cfg(target_os = "macos")]
pub fn get_memory_usage_macos(pid: u32) -> Result<u64> {
    use std::process::Command;
    
    // On macOS, we can use `ps` to get memory information
    let output = Command::new("ps")
        .args(&["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .map_err(|e| anyhow!("Failed to execute ps command: {}", e))?;
    
    if !output.status.success() {
        return Err(anyhow!("ps command failed"));
    }
    
    let rss_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let rss_kb = rss_str.parse::<u64>()
        .map_err(|e| anyhow!("Failed to parse RSS value '{}': {}", rss_str, e))?;
    
    // Return memory in bytes (ps gives it in KB)
    Ok(rss_kb * 1024)
} 