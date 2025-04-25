use anyhow::Result;
use std::time::Duration;
use tracing::info;

#[cfg(all(feature = "linux", target_os = "linux"))]
use nix::sys::resource::{getrlimit, setrlimit, Resource, Rlim};

/// Default resource limits for sandbox execution
pub struct ResourceLimits {
    /// Memory limit in megabytes
    pub memory_mb: u64,
    
    /// CPU time limit in seconds
    pub cpu_time_s: u64,
    
    /// Wall clock time limit in seconds
    pub timeout_s: u64,
    
    /// Maximum number of processes
    pub max_processes: u64,
    
    /// Maximum file size in megabytes
    pub max_file_size_mb: u64,
    
    /// Maximum number of open files
    pub max_open_files: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_mb: 512,
            cpu_time_s: 5,
            timeout_s: 10,
            max_processes: 10,
            max_file_size_mb: 50,
            max_open_files: 20,
        }
    }
}

#[cfg(all(feature = "linux", target_os = "linux"))]
pub fn apply_resource_limits(limits: &ResourceLimits) -> Result<()> {
    // Set memory limit (in bytes)
    let memory_limit_bytes = limits.memory_mb * 1024 * 1024;
    setrlimit(
        Resource::RLIMIT_AS,
        Rlim::from_raw(memory_limit_bytes),
        Rlim::from_raw(memory_limit_bytes),
    ).map_err(|e| anyhow::anyhow!("Failed to set memory limit: {}", e))?;
    
    // Set CPU time limit
    setrlimit(
        Resource::RLIMIT_CPU,
        Rlim::from_raw(limits.cpu_time_s),
        Rlim::from_raw(limits.cpu_time_s),
    ).map_err(|e| anyhow::anyhow!("Failed to set CPU time limit: {}", e))?;
    
    // Set process limit (prevent fork bombs)
    setrlimit(
        Resource::RLIMIT_NPROC,
        Rlim::from_raw(limits.max_processes),
        Rlim::from_raw(limits.max_processes),
    ).map_err(|e| anyhow::anyhow!("Failed to set process limit: {}", e))?;
    
    // Set file size limit
    let file_size_bytes = limits.max_file_size_mb * 1024 * 1024;
    setrlimit(
        Resource::RLIMIT_FSIZE,
        Rlim::from_raw(file_size_bytes),
        Rlim::from_raw(file_size_bytes),
    ).map_err(|e| anyhow::anyhow!("Failed to set file size limit: {}", e))?;
    
    // Set open files limit
    setrlimit(
        Resource::RLIMIT_NOFILE,
        Rlim::from_raw(limits.max_open_files),
        Rlim::from_raw(limits.max_open_files),
    ).map_err(|e| anyhow::anyhow!("Failed to set open files limit: {}", e))?;
    
    info!("Applied resource limits: memory={}MB, cpu={}s, processes={}, file_size={}MB, open_files={}",
          limits.memory_mb, limits.cpu_time_s, limits.max_processes, limits.max_file_size_mb, limits.max_open_files);
    
    Ok(())
}

#[cfg(not(all(feature = "linux", target_os = "linux")))]
pub fn apply_resource_limits(limits: &ResourceLimits) -> Result<()> {
    info!("Resource limits not fully supported on this platform");
    info!("Using software timeout of {}s only", limits.timeout_s);
    
    Ok(())
}

#[cfg(all(feature = "linux", target_os = "linux"))]
pub fn get_current_limits() -> Result<ResourceLimits> {
    let (mem_soft, _) = getrlimit(Resource::RLIMIT_AS)
        .map_err(|e| anyhow::anyhow!("Failed to get memory limit: {}", e))?;
    
    let (cpu_soft, _) = getrlimit(Resource::RLIMIT_CPU)
        .map_err(|e| anyhow::anyhow!("Failed to get CPU time limit: {}", e))?;
    
    let (proc_soft, _) = getrlimit(Resource::RLIMIT_NPROC)
        .map_err(|e| anyhow::anyhow!("Failed to get process limit: {}", e))?;
    
    let (file_soft, _) = getrlimit(Resource::RLIMIT_FSIZE)
        .map_err(|e| anyhow::anyhow!("Failed to get file size limit: {}", e))?;
    
    let (open_soft, _) = getrlimit(Resource::RLIMIT_NOFILE)
        .map_err(|e| anyhow::anyhow!("Failed to get open files limit: {}", e))?;
    
    let limits = ResourceLimits {
        memory_mb: mem_soft.as_raw() / (1024 * 1024),
        cpu_time_s: cpu_soft.as_raw(),
        timeout_s: 10,  // This is managed separately via tokio::time::timeout
        max_processes: proc_soft.as_raw(),
        max_file_size_mb: file_soft.as_raw() / (1024 * 1024),
        max_open_files: open_soft.as_raw(),
    };
    
    Ok(limits)
}

#[cfg(not(all(feature = "linux", target_os = "linux")))]
pub fn get_current_limits() -> Result<ResourceLimits> {
    // Return default limits on non-Linux platforms
    Ok(ResourceLimits::default())
}

pub struct ResourceStats {
    pub peak_memory_mb: u64,
    pub cpu_time_used_s: f64,
    pub wall_time_used_s: f64,
}

#[cfg(all(feature = "linux", target_os = "linux"))]
pub fn monitor_resources(pid: nix::unistd::Pid, interval: Duration) -> Result<ResourceStats> {
    info!("Monitoring resources for process {}", pid);
    
    // Create initial stats
    let mut stats = ResourceStats {
        peak_memory_mb: 0,
        cpu_time_used_s: 0.0,
        wall_time_used_s: 0.0,
    };
    
    let start_time = std::time::Instant::now();
    let pid_value = pid.as_raw() as u32;
    
    // Monitor the process for the specified interval
    let mut last_check = start_time;
    let mut last_cpu_usage = read_cpu_usage(pid_value)?;
    
    while last_check.elapsed() < interval {
        // Read current memory usage
        if let Ok(memory_kb) = read_memory_usage(pid_value) {
            let memory_mb = memory_kb / 1024;
            if memory_mb > stats.peak_memory_mb {
                stats.peak_memory_mb = memory_mb;
            }
        }
        
        // Read current CPU usage
        if let Ok(cpu_usage) = read_cpu_usage(pid_value) {
            stats.cpu_time_used_s = cpu_usage;
        }
        
        // Sleep briefly to reduce CPU usage of the monitoring itself
        std::thread::sleep(Duration::from_millis(100));
        last_check = std::time::Instant::now();
    }
    
    // Update wall time
    stats.wall_time_used_s = start_time.elapsed().as_secs_f64();
    
    Ok(stats)
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn read_memory_usage(pid: u32) -> Result<u64> {
    // Read memory usage from /proc/{pid}/status
    // VmRSS field shows the actual physical memory used by the process
    let status_content = std::fs::read_to_string(format!("/proc/{}/status", pid))
        .map_err(|e| anyhow::anyhow!("Failed to read process status: {}", e))?;
    
    // Parse VmRSS line to get memory usage in KB
    for line in status_content.lines() {
        if line.starts_with("VmRSS:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(memory_kb) = parts[1].parse::<u64>() {
                    return Ok(memory_kb);
                }
            }
        }
    }
    
    Err(anyhow::anyhow!("Could not find VmRSS field in process status"))
}

#[cfg(all(feature = "linux", target_os = "linux"))]
fn read_cpu_usage(pid: u32) -> Result<f64> {
    // Read CPU usage from /proc/{pid}/stat
    let stat_content = std::fs::read_to_string(format!("/proc/{}/stat", pid))
        .map_err(|e| anyhow::anyhow!("Failed to read process stat: {}", e))?;
    
    // Parse stat file to get CPU usage
    // Fields 14 and 15 are utime and stime (user and system CPU time)
    let parts: Vec<&str> = stat_content.split_whitespace().collect();
    if parts.len() < 15 {
        return Err(anyhow::anyhow!("Invalid format in process stat file"));
    }
    
    let utime = parts[13].parse::<u64>()
        .map_err(|e| anyhow::anyhow!("Failed to parse utime: {}", e))?;
    let stime = parts[14].parse::<u64>()
        .map_err(|e| anyhow::anyhow!("Failed to parse stime: {}", e))?;
    
    // Convert from clock ticks to seconds
    // Get clock ticks per second (usually 100 on Linux)
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
    let total_cpu_seconds = (utime + stime) as f64 / clk_tck as f64;
    
    Ok(total_cpu_seconds)
}

#[cfg(all(feature = "linux", target_os = "linux"))]
pub fn print_resource_report(stats: &ResourceStats) {
    info!("Resource usage report:");
    info!("  Peak memory usage: {} MB", stats.peak_memory_mb);
    info!("  CPU time used: {:.2} seconds", stats.cpu_time_used_s);
    info!("  Wall time used: {:.2} seconds", stats.wall_time_used_s);
    
    if stats.cpu_time_used_s > 0.0 && stats.wall_time_used_s > 0.0 {
        let cpu_efficiency = (stats.cpu_time_used_s / stats.wall_time_used_s) * 100.0;
        info!("  CPU efficiency: {:.1}%", cpu_efficiency);
    }
}

#[cfg(not(all(feature = "linux", target_os = "linux")))]
pub fn monitor_resources(_pid: u32, _interval: Duration) -> Result<ResourceStats> {
    // Return placeholder stats on non-Linux platforms
    let stats = ResourceStats {
        peak_memory_mb: 0,
        cpu_time_used_s: 0.0,
        wall_time_used_s: 0.0,
    };
    
    Ok(stats)
} 