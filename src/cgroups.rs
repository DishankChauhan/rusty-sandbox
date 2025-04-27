use anyhow::{Result, anyhow, Context};
use std::path::Path;
use tracing::{info, warn, error};

#[cfg(all(feature = "linux", target_os = "linux"))]
use cgroups_rs::{Cgroup, CgroupBuilder, Controller, cpu::CpuController, memory::MemController, blkio::BlkIoController};
#[cfg(all(feature = "linux", target_os = "linux"))]
use std::convert::TryFrom;

/// Resource limits configuration for cgroups
pub struct CgroupsConfig {
    /// Memory limit in bytes
    pub memory_limit_bytes: u64,
    
    /// CPU quota in microseconds per period
    pub cpu_quota_us: i64,
    
    /// CPU period in microseconds
    pub cpu_period_us: u64,
    
    /// CPU weight/shares (1-10000)
    pub cpu_shares: u64,
    
    /// I/O weight (10-1000)
    pub io_weight: u16,
    
    /// Maximum number of processes
    pub max_processes: u64,
}

impl Default for CgroupsConfig {
    fn default() -> Self {
        Self {
            memory_limit_bytes: 512 * 1024 * 1024, // 512MB
            cpu_quota_us: 100_000,                // 100ms
            cpu_period_us: 1_000_000,             // 1s (so 10% CPU)
            cpu_shares: 1024,                     // Normal weight
            io_weight: 100,                       // Normal weight
            max_processes: 10,                    // 10 processes max
        }
    }
}

/// Create a cgroup for a process and apply resource limits
#[cfg(all(feature = "linux", target_os = "linux"))]
pub fn setup_cgroup(pid: u32, name: &str, config: &CgroupsConfig) -> Result<CgroupHandle> {
    // Create a unique cgroup name
    let cgroup_name = format!("rusty-sandbox-{}-{}", name, pid);
    
    info!("Setting up cgroup: {}", cgroup_name);
    
    // Check if cgroups v2 is available
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return Err(anyhow!("Cgroups v2 unified hierarchy not found. Make sure your system is using cgroups v2."));
    }
    
    // Create the cgroup
    let cgroup = CgroupBuilder::new(&cgroup_name)
        .build()
        .map_err(|e| anyhow!("Failed to create cgroup: {}", e))?;
    
    // Configure memory limits
    if let Some(memory_controller) = cgroup.controller_of::<MemController>() {
        memory_controller
            .set_memory_hard_limit(config.memory_limit_bytes)
            .map_err(|e| anyhow!("Failed to set memory limit: {}", e))?;
        
        // Set OOM control to kill the process when it exceeds memory
        memory_controller
            .set_oom_control(false)
            .map_err(|e| anyhow!("Failed to set OOM control: {}", e))?;
    } else {
        warn!("Memory controller not available");
    }
    
    // Configure CPU limits
    if let Some(cpu_controller) = cgroup.controller_of::<CpuController>() {
        // Set CPU quota
        cpu_controller
            .set_cfs_quota(config.cpu_quota_us)
            .map_err(|e| anyhow!("Failed to set CPU quota: {}", e))?;
            
        // Set CPU period
        cpu_controller
            .set_cfs_period(config.cpu_period_us)
            .map_err(|e| anyhow!("Failed to set CPU period: {}", e))?;
            
        // Set CPU shares
        cpu_controller
            .set_shares(config.cpu_shares)
            .map_err(|e| anyhow!("Failed to set CPU shares: {}", e))?;
    } else {
        warn!("CPU controller not available");
    }
    
    // Configure I/O limits if available
    if let Some(blkio_controller) = cgroup.controller_of::<BlkIoController>() {
        blkio_controller
            .set_weight(config.io_weight)
            .map_err(|e| anyhow!("Failed to set I/O weight: {}", e))?;
    } else {
        warn!("BlkIO controller not available");
    }
    
    // Add the process to the cgroup
    cgroup
        .add_task_by_tgid(pid as u64)
        .map_err(|e| anyhow!("Failed to add process to cgroup: {}", e))?;
    
    info!("Successfully set up cgroup for PID {}", pid);
    
    Ok(CgroupHandle {
        cgroup,
        cgroup_name: cgroup_name.to_string(),
    })
}

/// Handle for managing the cgroup lifecycle
#[cfg(all(feature = "linux", target_os = "linux"))]
pub struct CgroupHandle {
    cgroup: Cgroup,
    cgroup_name: String,
}

#[cfg(all(feature = "linux", target_os = "linux"))]
impl CgroupHandle {
    /// Get the current memory usage of the cgroup in bytes
    pub fn get_memory_usage(&self) -> Result<u64> {
        let memory_controller = self.cgroup.controller_of::<MemController>()
            .ok_or_else(|| anyhow!("Memory controller not available"))?;
        
        memory_controller.memory_stat()
            .map(|stats| stats.usage_in_bytes)
            .map_err(|e| anyhow!("Failed to get memory usage: {}", e))
    }
    
    /// Get the current CPU usage of the cgroup
    pub fn get_cpu_usage(&self) -> Result<u64> {
        let cpu_controller = self.cgroup.controller_of::<CpuController>()
            .ok_or_else(|| anyhow!("CPU controller not available"))?;
        
        cpu_controller.cpu_stat()
            .map(|stats| stats.usage_usec)
            .map_err(|e| anyhow!("Failed to get CPU usage: {}", e))
    }
    
    /// Remove the cgroup, releasing all resources
    pub fn cleanup(&self) -> Result<()> {
        info!("Cleaning up cgroup: {}", self.cgroup_name);
        self.cgroup.delete()
            .map_err(|e| anyhow!("Failed to delete cgroup: {}", e))?;
        Ok(())
    }
}

/// Non-Linux placeholder for cgroup setup
#[cfg(not(all(feature = "linux", target_os = "linux")))]
pub fn setup_cgroup(_pid: u32, _name: &str, _config: &CgroupsConfig) -> Result<()> {
    warn!("Cgroups not supported on this platform. Resource limits will be best-effort only.");
    Ok(())
}

/// Non-Linux placeholder for cgroup handle
#[cfg(not(all(feature = "linux", target_os = "linux")))]
pub struct CgroupHandle;

#[cfg(not(all(feature = "linux", target_os = "linux")))]
impl CgroupHandle {
    pub fn get_memory_usage(&self) -> Result<u64> {
        Err(anyhow!("Cgroups not supported on this platform"))
    }
    
    pub fn get_cpu_usage(&self) -> Result<u64> {
        Err(anyhow!("Cgroups not supported on this platform"))
    }
    
    pub fn cleanup(&self) -> Result<()> {
        Ok(())
    }
}

/// Represents a cgroup resource configuration for resource limits
#[derive(Debug, Clone)]
pub struct CgroupConfig {
    /// Memory limit in bytes
    pub memory_limit_bytes: Option<u64>,
    /// Memory+swap limit in bytes
    pub memory_swap_limit_bytes: Option<u64>,
    /// CPU shares (relative weight)
    pub cpu_shares: Option<u64>,
    /// CPU quota (in microseconds)
    pub cpu_quota_us: Option<i64>,
    /// CPU period (in microseconds)
    pub cpu_period_us: Option<u64>,
    /// Number of CPUs to limit to (alternative to quota/period)
    pub cpu_max: Option<(u64, u64)>,
    /// Block IO weight
    pub io_weight: Option<u16>,
    /// Maximum processes/threads in the cgroup
    pub pids_max: Option<i64>,
    /// Maximum file descriptors
    pub files_max: Option<u64>,
}

impl Default for CgroupConfig {
    fn default() -> Self {
        Self {
            memory_limit_bytes: None,
            memory_swap_limit_bytes: None,
            cpu_shares: None,
            cpu_quota_us: None,
            cpu_period_us: None,
            cpu_max: None,
            io_weight: None,
            pids_max: None,
            files_max: None,
        }
    }
}

impl CgroupConfig {
    /// Create a new cgroup configuration with moderate limits
    pub fn moderate() -> Self {
        Self {
            memory_limit_bytes: Some(512 * 1024 * 1024), // 512 MB
            memory_swap_limit_bytes: Some(768 * 1024 * 1024), // 768 MB
            cpu_max: Some((50000, 100000)), // 50% CPU
            pids_max: Some(100),
            io_weight: Some(50),
            files_max: Some(1024),
            ..Default::default()
        }
    }

    /// Create a new cgroup configuration with strict limits
    pub fn strict() -> Self {
        Self {
            memory_limit_bytes: Some(256 * 1024 * 1024), // 256 MB
            memory_swap_limit_bytes: Some(256 * 1024 * 1024), // No swap
            cpu_max: Some((20000, 100000)), // 20% CPU
            pids_max: Some(50),
            io_weight: Some(25),
            files_max: Some(512),
            ..Default::default()
        }
    }
}

/// Manages cgroups v2 for resource isolation
pub struct CgroupManager {
    /// Base path for cgroups
    base_path: PathBuf,
    /// Cgroup name
    name: String,
    /// Full path to the cgroup
    cgroup_path: PathBuf,
    /// Whether the cgroup has been created
    created: bool,
}

impl CgroupManager {
    /// Create a new cgroup manager with a unique name
    pub fn new(name: &str) -> Result<Self> {
        // Check if cgroups v2 is available
        if !is_cgroupv2_available() {
            return Err(anyhow!("cgroups v2 is not available on this system"));
        }

        let base_path = get_cgroup_mount_point()?;
        let cgroup_path = base_path.join(name);

        Ok(Self {
            base_path,
            name: name.to_string(),
            cgroup_path,
            created: false,
        })
    }

    /// Create the cgroup
    pub fn create(&mut self) -> Result<()> {
        if self.created {
            return Ok(());
        }

        // Create the cgroup directory
        fs::create_dir_all(&self.cgroup_path)
            .with_context(|| format!("Failed to create cgroup directory at {:?}", self.cgroup_path))?;

        self.created = true;
        info!("Created cgroup: {}", self.name);
        Ok(())
    }

    /// Apply resource limits defined in the config
    pub fn apply_limits(&self, config: &CgroupConfig) -> Result<()> {
        if !self.created {
            return Err(anyhow!("Cgroup must be created before applying limits"));
        }

        // Apply memory limits
        if let Some(memory_limit) = config.memory_limit_bytes {
            self.write_cgroup_file("memory.max", &memory_limit.to_string())?;
        }

        if let Some(memory_swap_limit) = config.memory_swap_limit_bytes {
            self.write_cgroup_file("memory.swap.max", &memory_swap_limit.to_string())?;
        }

        // Apply CPU limits
        if let Some((quota, period)) = config.cpu_max {
            self.write_cgroup_file("cpu.max", &format!("{} {}", quota, period))?;
        } else {
            if let Some(quota) = config.cpu_quota_us {
                if let Some(period) = config.cpu_period_us {
                    self.write_cgroup_file("cpu.max", &format!("{} {}", quota, period))?;
                }
            }
        }

        if let Some(weight) = config.cpu_shares {
            self.write_cgroup_file("cpu.weight", &weight.to_string())?;
        }

        // Apply IO limits
        if let Some(weight) = config.io_weight {
            self.write_cgroup_file("io.weight", &weight.to_string())?;
        }

        // Apply PID limits
        if let Some(pids_max) = config.pids_max {
            self.write_cgroup_file("pids.max", &pids_max.to_string())?;
        }

        info!("Applied resource limits to cgroup: {}", self.name);
        Ok(())
    }

    /// Add a process to the cgroup
    pub fn add_process(&self, pid: u32) -> Result<()> {
        if !self.created {
            return Err(anyhow!("Cgroup must be created before adding processes"));
        }

        self.write_cgroup_file("cgroup.procs", &pid.to_string())?;
        info!("Added process {} to cgroup: {}", pid, self.name);
        Ok(())
    }

    /// Read current memory usage
    pub fn get_memory_usage(&self) -> Result<u64> {
        let usage = self.read_cgroup_file("memory.current")?;
        usage.trim().parse::<u64>()
            .map_err(|e| anyhow!("Failed to parse memory usage: {}", e))
    }

    /// Read current CPU usage
    pub fn get_cpu_usage(&self) -> Result<String> {
        self.read_cgroup_file("cpu.stat")
    }

    /// Read current IO usage
    pub fn get_io_usage(&self) -> Result<String> {
        self.read_cgroup_file("io.stat")
    }

    /// Remove the cgroup
    pub fn remove(&self) -> Result<()> {
        if !self.created {
            return Ok(());
        }

        // First make sure the cgroup is empty
        self.write_cgroup_file("cgroup.procs", "0")?;

        // Remove the cgroup directory
        fs::remove_dir(&self.cgroup_path)
            .with_context(|| format!("Failed to remove cgroup directory at {:?}", self.cgroup_path))?;

        info!("Removed cgroup: {}", self.name);
        Ok(())
    }

    /// Write a value to a cgroup control file
    fn write_cgroup_file(&self, control_file: &str, value: &str) -> Result<()> {
        let path = self.cgroup_path.join(control_file);
        let mut file = OpenOptions::new()
            .write(true)
            .open(&path)
            .with_context(|| format!("Failed to open cgroup control file {:?}", path))?;

        file.write_all(value.as_bytes())
            .with_context(|| format!("Failed to write to cgroup control file {:?}", path))?;

        debug!("Wrote '{}' to cgroup file: {}", value, control_file);
        Ok(())
    }

    /// Read a value from a cgroup control file
    fn read_cgroup_file(&self, control_file: &str) -> Result<String> {
        let path = self.cgroup_path.join(control_file);
        fs::read_to_string(&path)
            .with_context(|| format!("Failed to read cgroup control file {:?}", path))
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        if self.created {
            if let Err(e) = self.remove() {
                error!("Failed to remove cgroup on drop: {}", e);
            }
        }
    }
}

/// Check if cgroups v2 is available on the system
fn is_cgroupv2_available() -> bool {
    // Check if the system is using cgroups v2 (unified hierarchy)
    if let Ok(out) = Command::new("mount")
        .output() {
            let output = String::from_utf8_lossy(&out.stdout);
            output.contains("cgroup2") || output.contains("type cgroup2")
        } else {
            false
        }
}

/// Get the cgroup v2 mount point
fn get_cgroup_mount_point() -> Result<PathBuf> {
    // First try standard locations
    let standard_paths = [
        "/sys/fs/cgroup",
        "/mnt/cgroup",
    ];

    for path in &standard_paths {
        let p = Path::new(path);
        if p.exists() && fs::metadata(p)?.is_dir() {
            return Ok(p.to_path_buf());
        }
    }

    // Try to find it from mount output
    if let Ok(out) = Command::new("mount")
        .output() {
            let output = String::from_utf8_lossy(&out.stdout);
            for line in output.lines() {
                if line.contains("cgroup2") || line.contains("type cgroup2") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let mount_point = parts[2];
                        return Ok(PathBuf::from(mount_point));
                    }
                }
            }
        }

    Err(anyhow!("Could not determine cgroup v2 mount point"))
}

/// Create a sandbox-ready cgroup with appropriate permissions
pub fn setup_sandbox_cgroup(name: &str, config: &CgroupConfig) -> Result<CgroupManager> {
    let mut manager = CgroupManager::new(name)?;
    manager.create()?;
    manager.apply_limits(config)?;
    
    // Ensure delegation is enabled to allow nested controllers
    manager.write_cgroup_file("cgroup.subtree_control", "+memory +cpu +io +pids")?;
    
    Ok(manager)
} 