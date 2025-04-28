use anyhow::{Result, anyhow, Context};
use std::path::Path;
use tracing::{info, warn, error};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::process::Command;
use std::path::PathBuf;

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

/// CGroup version
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CgroupVersion {
    /// CGroup v1 (legacy)
    V1,
    /// CGroup v2 (unified)
    V2,
    /// No CGroups available
    None,
}

/// CGroup subsystem to manage
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CgroupSubsystem {
    Cpu,
    Memory,
    PidsLimit,
    BlockIO,
    Devices,
    Network,
}

impl CgroupSubsystem {
    /// Get the name of the subsystem for cgroup v1
    pub fn name_v1(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::PidsLimit => "pids",
            Self::BlockIO => "blkio",
            Self::Devices => "devices",
            Self::Network => "net_cls,net_prio",
        }
    }
    
    /// Get the prefix for files in cgroup v2
    pub fn prefix_v2(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::PidsLimit => "pids",
            Self::BlockIO => "io",
            Self::Devices => "devices",
            Self::Network => "net",
        }
    }
}

/// Manages cgroup resources for sandboxed processes
pub struct CgroupManager {
    /// The version of cgroups available on this system
    version: CgroupVersion,
    /// Path to the cgroup
    cgroup_path: PathBuf,
    /// Name of the cgroup
    group_name: String,
    /// Subsystems enabled
    subsystems: Vec<CgroupSubsystem>,
    /// Whether the cgroup has been created
    created: bool,
}

impl CgroupManager {
    /// Create a new cgroup manager
    pub fn new(group_name: &str) -> Result<Self> {
        // Determine CGroup version
        let version = Self::detect_cgroup_version()?;
        
        // Get the path to the cgroup
        let cgroup_path = match version {
            CgroupVersion::V1 => PathBuf::from("/sys/fs/cgroup"),
            CgroupVersion::V2 => PathBuf::from("/sys/fs/cgroup"),
            CgroupVersion::None => return Err(anyhow!("CGroups not available on this system")),
        };
        
        Ok(Self {
            version,
            cgroup_path,
            group_name: group_name.to_string(),
            subsystems: vec![],
            created: false,
        })
    }
    
    /// Detect the cgroup version available on this system
    fn detect_cgroup_version() -> Result<CgroupVersion> {
        // Check if cgroup v2 is mounted
        let cgroup_v2_path = Path::new("/sys/fs/cgroup");
        if cgroup_v2_path.exists() {
            // Check if cgroup.controllers exists (v2 indicator)
            let controllers_path = cgroup_v2_path.join("cgroup.controllers");
            if controllers_path.exists() {
                return Ok(CgroupVersion::V2);
            }
            
            // Check for legacy v1 directories
            let cpu_path = cgroup_v2_path.join("cpu");
            let memory_path = cgroup_v2_path.join("memory");
            
            if cpu_path.exists() && memory_path.exists() {
                return Ok(CgroupVersion::V1);
            }
        }
        
        // Check for v1 mounts directly
        let mounts_output = Command::new("mount")
            .output()
            .map_err(|e| anyhow!("Failed to execute mount command: {}", e))?;
            
        let mounts_str = String::from_utf8_lossy(&mounts_output.stdout);
        if mounts_str.contains("cgroup") {
            return Ok(CgroupVersion::V1);
        }
        
        // No cgroups found
        Ok(CgroupVersion::None)
    }
    
    /// Enable a specific cgroup subsystem
    pub fn enable_subsystem(&mut self, subsystem: CgroupSubsystem) -> &mut Self {
        if !self.subsystems.contains(&subsystem) {
            self.subsystems.push(subsystem);
        }
        self
    }
    
    /// Create the cgroup
    pub fn create(&mut self) -> Result<()> {
        if self.created {
            return Ok(());
        }
        
        match self.version {
            CgroupVersion::V1 => self.create_v1()?,
            CgroupVersion::V2 => self.create_v2()?,
            CgroupVersion::None => return Err(anyhow!("CGroups not available on this system")),
        }
        
        self.created = true;
        Ok(())
    }
    
    /// Create cgroup v1
    fn create_v1(&self) -> Result<()> {
        for subsystem in &self.subsystems {
            let subsys_path = self.cgroup_path.join(subsystem.name_v1()).join(&self.group_name);
            
            // Create the directory if it doesn't exist
            if !subsys_path.exists() {
                fs::create_dir_all(&subsys_path)
                    .map_err(|e| anyhow!("Failed to create cgroup directory {}: {}", 
                                        subsys_path.display(), e))?;
            }
            
            info!("Created cgroup v1 {} for subsystem {}", 
                  self.group_name, subsystem.name_v1());
        }
        
        Ok(())
    }
    
    /// Create cgroup v2
    fn create_v2(&self) -> Result<()> {
        let group_path = self.cgroup_path.join(&self.group_name);
        
        // Create the directory if it doesn't exist
        if !group_path.exists() {
            fs::create_dir_all(&group_path)
                .map_err(|e| anyhow!("Failed to create cgroup directory {}: {}", 
                                    group_path.display(), e))?;
        }
        
        // Enable controllers
        let controllers_file = self.cgroup_path.join("cgroup.controllers");
        let subtree_control = self.cgroup_path.join("cgroup.subtree_control");
        
        if controllers_file.exists() && subtree_control.exists() {
            // Read available controllers
            let mut content = String::new();
            File::open(controllers_file)
                .map_err(|e| anyhow!("Failed to open cgroup.controllers: {}", e))?
                .read_to_string(&mut content)
                .map_err(|e| anyhow!("Failed to read cgroup.controllers: {}", e))?;
                
            // Enable controllers in parent
            let mut subtree_file = File::create(subtree_control)
                .map_err(|e| anyhow!("Failed to open cgroup.subtree_control: {}", e))?;
                
            for controller in content.split_whitespace() {
                let _ = write!(subtree_file, "+{} ", controller);
            }
        }
        
        info!("Created cgroup v2 {}", self.group_name);
        Ok(())
    }
    
    /// Add a process to the cgroup
    pub fn add_process(&self, pid: u32) -> Result<()> {
        if !self.created {
            return Err(anyhow!("CGroup not created yet"));
        }
        
        match self.version {
            CgroupVersion::V1 => self.add_process_v1(pid)?,
            CgroupVersion::V2 => self.add_process_v2(pid)?,
            CgroupVersion::None => return Err(anyhow!("CGroups not available on this system")),
        }
        
        Ok(())
    }
    
    /// Add a process to cgroup v1
    fn add_process_v1(&self, pid: u32) -> Result<()> {
        for subsystem in &self.subsystems {
            let tasks_path = self.cgroup_path
                .join(subsystem.name_v1())
                .join(&self.group_name)
                .join("tasks");
                
            let mut file = File::create(&tasks_path)
                .map_err(|e| anyhow!("Failed to open {} for writing: {}", tasks_path.display(), e))?;
                
            write!(file, "{}", pid)
                .map_err(|e| anyhow!("Failed to write PID {} to {}: {}", 
                                      pid, tasks_path.display(), e))?;
        }
        
        info!("Added process {} to cgroup v1 {}", pid, self.group_name);
        Ok(())
    }
    
    /// Add a process to cgroup v2
    fn add_process_v2(&self, pid: u32) -> Result<()> {
        let procs_path = self.cgroup_path
            .join(&self.group_name)
            .join("cgroup.procs");
            
        let mut file = File::create(&procs_path)
            .map_err(|e| anyhow!("Failed to open {} for writing: {}", procs_path.display(), e))?;
            
        write!(file, "{}", pid)
            .map_err(|e| anyhow!("Failed to write PID {} to {}: {}", 
                                  pid, procs_path.display(), e))?;
                                  
        info!("Added process {} to cgroup v2 {}", pid, self.group_name);
        Ok(())
    }
    
    /// Set CPU limits for the cgroup
    pub fn set_cpu_limit(&self, cpu_quota: u64, cpu_period: u64) -> Result<()> {
        if !self.created {
            return Err(anyhow!("CGroup not created yet"));
        }
        
        match self.version {
            CgroupVersion::V1 => {
                let quota_path = self.cgroup_path
                    .join("cpu")
                    .join(&self.group_name)
                    .join("cpu.cfs_quota_us");
                    
                let period_path = self.cgroup_path
                    .join("cpu")
                    .join(&self.group_name)
                    .join("cpu.cfs_period_us");
                    
                let mut quota_file = File::create(&quota_path)
                    .map_err(|e| anyhow!("Failed to open {} for writing: {}", quota_path.display(), e))?;
                    
                let mut period_file = File::create(&period_path)
                    .map_err(|e| anyhow!("Failed to open {} for writing: {}", period_path.display(), e))?;
                    
                write!(quota_file, "{}", cpu_quota)
                    .map_err(|e| anyhow!("Failed to write quota: {}", e))?;
                    
                write!(period_file, "{}", cpu_period)
                    .map_err(|e| anyhow!("Failed to write period: {}", e))?;
            },
            CgroupVersion::V2 => {
                let max_path = self.cgroup_path
                    .join(&self.group_name)
                    .join("cpu.max");
                    
                let mut max_file = File::create(&max_path)
                    .map_err(|e| anyhow!("Failed to open {} for writing: {}", max_path.display(), e))?;
                    
                write!(max_file, "{} {}", cpu_quota, cpu_period)
                    .map_err(|e| anyhow!("Failed to write CPU max: {}", e))?;
            },
            CgroupVersion::None => return Err(anyhow!("CGroups not available on this system")),
        }
        
        info!("Set CPU limit quota={} period={} for cgroup {}", 
              cpu_quota, cpu_period, self.group_name);
        Ok(())
    }
    
    /// Set memory limit for the cgroup
    pub fn set_memory_limit(&self, memory_bytes: u64) -> Result<()> {
        if !self.created {
            return Err(anyhow!("CGroup not created yet"));
        }
        
        match self.version {
            CgroupVersion::V1 => {
                let limit_path = self.cgroup_path
                    .join("memory")
                    .join(&self.group_name)
                    .join("memory.limit_in_bytes");
                    
                let mut limit_file = File::create(&limit_path)
                    .map_err(|e| anyhow!("Failed to open {} for writing: {}", limit_path.display(), e))?;
                    
                write!(limit_file, "{}", memory_bytes)
                    .map_err(|e| anyhow!("Failed to write memory limit: {}", e))?;
            },
            CgroupVersion::V2 => {
                let max_path = self.cgroup_path
                    .join(&self.group_name)
                    .join("memory.max");
                    
                let mut max_file = File::create(&max_path)
                    .map_err(|e| anyhow!("Failed to open {} for writing: {}", max_path.display(), e))?;
                    
                write!(max_file, "{}", memory_bytes)
                    .map_err(|e| anyhow!("Failed to write memory max: {}", e))?;
            },
            CgroupVersion::None => return Err(anyhow!("CGroups not available on this system")),
        }
        
        info!("Set memory limit {} bytes for cgroup {}", memory_bytes, self.group_name);
        Ok(())
    }
    
    /// Set process limit for the cgroup
    pub fn set_pids_limit(&self, max_pids: u64) -> Result<()> {
        if !self.created {
            return Err(anyhow!("CGroup not created yet"));
        }
        
        match self.version {
            CgroupVersion::V1 => {
                let limit_path = self.cgroup_path
                    .join("pids")
                    .join(&self.group_name)
                    .join("pids.max");
                    
                let mut limit_file = File::create(&limit_path)
                    .map_err(|e| anyhow!("Failed to open {} for writing: {}", limit_path.display(), e))?;
                    
                write!(limit_file, "{}", max_pids)
                    .map_err(|e| anyhow!("Failed to write pids limit: {}", e))?;
            },
            CgroupVersion::V2 => {
                let max_path = self.cgroup_path
                    .join(&self.group_name)
                    .join("pids.max");
                    
                let mut max_file = File::create(&max_path)
                    .map_err(|e| anyhow!("Failed to open {} for writing: {}", max_path.display(), e))?;
                    
                write!(max_file, "{}", max_pids)
                    .map_err(|e| anyhow!("Failed to write pids max: {}", e))?;
            },
            CgroupVersion::None => return Err(anyhow!("CGroups not available on this system")),
        }
        
        info!("Set pids limit {} for cgroup {}", max_pids, self.group_name);
        Ok(())
    }
    
    /// Check if a process is in the cgroup
    pub fn is_process_in_cgroup(&self, pid: u32) -> Result<bool> {
        if !self.created {
            return Ok(false);
        }
        
        match self.version {
            CgroupVersion::V1 => {
                if self.subsystems.is_empty() {
                    return Ok(false);
                }
                
                // Use the first subsystem to check
                let subsystem = self.subsystems[0];
                let cgroup_file = PathBuf::from(format!("/proc/{}/cgroup", pid));
                
                if !cgroup_file.exists() {
                    return Ok(false);
                }
                
                let content = fs::read_to_string(cgroup_file)
                    .map_err(|e| anyhow!("Failed to read /proc/{}/cgroup: {}", pid, e))?;
                    
                // Look for the subsystem in the cgroup file
                for line in content.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 3 {
                        let subsys = parts[1];
                        let path = parts[2];
                        
                        if subsys.contains(subsystem.name_v1()) && 
                           path.ends_with(&self.group_name) {
                            return Ok(true);
                        }
                    }
                }
                
                Ok(false)
            },
            CgroupVersion::V2 => {
                let cgroup_file = PathBuf::from(format!("/proc/{}/cgroup", pid));
                
                if !cgroup_file.exists() {
                    return Ok(false);
                }
                
                let content = fs::read_to_string(cgroup_file)
                    .map_err(|e| anyhow!("Failed to read /proc/{}/cgroup: {}", pid, e))?;
                    
                // In v2, there's only one line with the path
                for line in content.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 3 {
                        let path = parts[2];
                        
                        if path.ends_with(&self.group_name) {
                            return Ok(true);
                        }
                    }
                }
                
                Ok(false)
            },
            CgroupVersion::None => Ok(false),
        }
    }
    
    /// Get current CPU usage from the cgroup
    pub fn get_cpu_usage(&self) -> Result<f64> {
        if !self.created {
            return Err(anyhow!("CGroup not created yet"));
        }
        
        match self.version {
            CgroupVersion::V1 => {
                let usage_path = self.cgroup_path
                    .join("cpu")
                    .join(&self.group_name)
                    .join("cpuacct.usage");
                    
                if !usage_path.exists() {
                    return Ok(0.0);
                }
                
                let content = fs::read_to_string(usage_path)
                    .map_err(|e| anyhow!("Failed to read CPU usage: {}", e))?;
                    
                let usage = content.trim().parse::<u64>()
                    .map_err(|e| anyhow!("Failed to parse CPU usage: {}", e))?;
                    
                // Convert to percentage (usage is in nanoseconds)
                let cores = num_cpus::get() as f64;
                let usage_sec = usage as f64 / 1_000_000_000.0;
                
                // This is a rough approximation, in reality you'd want to
                // calculate the delta over time
                Ok(usage_sec * 100.0 / cores)
            },
            CgroupVersion::V2 => {
                let usage_path = self.cgroup_path
                    .join(&self.group_name)
                    .join("cpu.stat");
                    
                if !usage_path.exists() {
                    return Ok(0.0);
                }
                
                let content = fs::read_to_string(usage_path)
                    .map_err(|e| anyhow!("Failed to read CPU stats: {}", e))?;
                    
                let mut usage = 0;
                
                for line in content.lines() {
                    if line.starts_with("usage_usec") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            usage = parts[1].parse::<u64>()
                                .map_err(|e| anyhow!("Failed to parse CPU usage: {}", e))?;
                            break;
                        }
                    }
                }
                
                // Convert to percentage (usage is in microseconds)
                let cores = num_cpus::get() as f64;
                let usage_sec = usage as f64 / 1_000_000.0;
                
                // This is a rough approximation, in reality you'd want to
                // calculate the delta over time
                Ok(usage_sec * 100.0 / cores)
            },
            CgroupVersion::None => Ok(0.0),
        }
    }
    
    /// Get current memory usage from the cgroup
    pub fn get_memory_usage(&self) -> Result<u64> {
        if !self.created {
            return Err(anyhow!("CGroup not created yet"));
        }
        
        match self.version {
            CgroupVersion::V1 => {
                let usage_path = self.cgroup_path
                    .join("memory")
                    .join(&self.group_name)
                    .join("memory.usage_in_bytes");
                    
                if !usage_path.exists() {
                    return Ok(0);
                }
                
                let content = fs::read_to_string(usage_path)
                    .map_err(|e| anyhow!("Failed to read memory usage: {}", e))?;
                    
                content.trim().parse::<u64>()
                    .map_err(|e| anyhow!("Failed to parse memory usage: {}", e))
            },
            CgroupVersion::V2 => {
                let usage_path = self.cgroup_path
                    .join(&self.group_name)
                    .join("memory.current");
                    
                if !usage_path.exists() {
                    return Ok(0);
                }
                
                let content = fs::read_to_string(usage_path)
                    .map_err(|e| anyhow!("Failed to read memory usage: {}", e))?;
                    
                content.trim().parse::<u64>()
                    .map_err(|e| anyhow!("Failed to parse memory usage: {}", e))
            },
            CgroupVersion::None => Ok(0),
        }
    }
    
    /// Cleanup the cgroup on drop
    fn cleanup(&self) -> Result<()> {
        if !self.created {
            return Ok(());
        }
        
        match self.version {
            CgroupVersion::V1 => {
                for subsystem in &self.subsystems {
                    let subsys_path = self.cgroup_path
                        .join(subsystem.name_v1())
                        .join(&self.group_name);
                        
                    // First, move all processes to the root cgroup
                    let tasks_path = subsys_path.join("tasks");
                    if tasks_path.exists() {
                        let content = fs::read_to_string(&tasks_path).unwrap_or_default();
                        
                        for pid in content.lines() {
                            let root_tasks = self.cgroup_path
                                .join(subsystem.name_v1())
                                .join("tasks");
                                
                            let _ = fs::write(&root_tasks, pid);
                        }
                    }
                    
                    // Then remove the directory
                    if subsys_path.exists() {
                        let _ = fs::remove_dir(&subsys_path);
                    }
                }
            },
            CgroupVersion::V2 => {
                let group_path = self.cgroup_path.join(&self.group_name);
                
                // First, move all processes to the root cgroup
                let procs_path = group_path.join("cgroup.procs");
                if procs_path.exists() {
                    let content = fs::read_to_string(&procs_path).unwrap_or_default();
                    
                    for pid in content.lines() {
                        let root_procs = self.cgroup_path.join("cgroup.procs");
                        let _ = fs::write(&root_procs, pid);
                    }
                }
                
                // Then remove the directory
                if group_path.exists() {
                    let _ = fs::remove_dir(&group_path);
                }
            },
            CgroupVersion::None => {},
        }
        
        Ok(())
    }
    
    /// Apply resource limits defined in CgroupConfig to the cgroup
    pub fn apply_limits(&self, config: &CgroupConfig) -> Result<()> {
        if !self.created {
            return Err(anyhow!("CGroup not created yet"));
        }
        
        // Apply CPU limits if configured
        if let Some(shares) = config.cpu_shares {
            self.set_cpu_shares(shares)?;
        }
        
        if let Some(quota) = config.cpu_quota_us {
            if let Some(period) = config.cpu_period_us {
                self.set_cpu_limit(period as u64, quota as u64)?;
            }
        }
        
        // Apply memory limits if configured
        if let Some(mem_limit) = config.memory_limit_bytes {
            self.set_memory_limit(mem_limit)?;
        }
        
        // Apply PIDs limit if configured
        if let Some(pids_max) = config.pids_max {
            self.set_pids_limit(pids_max as u64)?;
        }
        
        Ok(())
    }
    
    /// Set CPU shares (relative weight)
    pub fn set_cpu_shares(&self, shares: u64) -> Result<()> {
        if !self.created {
            return Err(anyhow!("CGroup not created yet"));
        }
        
        match self.version {
            CgroupVersion::V1 => {
                let cpu_shares_path = self.cgroup_path
                    .join("cpu")
                    .join(&self.group_name)
                    .join("cpu.shares");
                    
                fs::write(cpu_shares_path, shares.to_string())
                    .map_err(|e| anyhow!("Failed to set CPU shares: {}", e))?;
            },
            CgroupVersion::V2 => {
                let cpu_weight_path = self.cgroup_path
                    .join(&self.group_name)
                    .join("cpu.weight");
                    
                // Convert from shares (1-1024) to weight (1-10000)
                let weight = (shares * 10).min(10000);
                
                fs::write(cpu_weight_path, weight.to_string())
                    .map_err(|e| anyhow!("Failed to set CPU weight: {}", e))?;
            },
            CgroupVersion::None => {},
        }
        
        Ok(())
    }
    
    /// Write to a cgroup control file
    pub fn write_cgroup_file(&self, filename: &str, value: &str) -> Result<()> {
        if !self.created {
            return Err(anyhow!("CGroup not created yet"));
        }
        
        match self.version {
            CgroupVersion::V1 => {
                // In v1, control files are in subsystem subdirectories
                for subsystem in &self.subsystems {
                    let file_path = self.cgroup_path
                        .join(subsystem.name_v1())
                        .join(&self.group_name)
                        .join(filename);
                        
                    if file_path.exists() {
                        fs::write(&file_path, value)
                            .map_err(|e| anyhow!("Failed to write to {}: {}", file_path.display(), e))?;
                        
                        // For cgroup.subtree_control, this is likely only in one subsystem
                        if filename == "cgroup.subtree_control" {
                            break;
                        }
                    }
                }
            },
            CgroupVersion::V2 => {
                let file_path = self.cgroup_path
                    .join(&self.group_name)
                    .join(filename);
                    
                if file_path.exists() {
                    fs::write(&file_path, value)
                        .map_err(|e| anyhow!("Failed to write to {}: {}", file_path.display(), e))?;
                }
            },
            CgroupVersion::None => {},
        }
        
        Ok(())
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
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