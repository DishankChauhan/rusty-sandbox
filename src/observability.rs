use anyhow::{Result, anyhow, Context};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, error, instrument};
use std::sync::{Arc, Mutex};

#[cfg(all(feature = "linux", target_os = "linux"))]
use procfs::process::{Process, Stat};

/// Observability metrics collected for a sandbox run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionMetrics {
    /// Execution start time (timestamp)
    pub start_time: chrono::DateTime<chrono::Utc>,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Peak memory usage in bytes
    pub peak_memory_bytes: u64,
    /// Average CPU usage as percentage (0-100)
    pub avg_cpu_usage: f64,
    /// Maximum CPU usage as percentage (0-100)
    pub max_cpu_usage: f64,
    /// Total I/O bytes read
    pub io_bytes_read: u64,
    /// Total I/O bytes written
    pub io_bytes_written: u64,
    /// Number of context switches
    pub context_switches: u64,
    /// Number of syscalls made
    pub syscall_count: u64,
    /// Map of specific syscall names to counts
    pub syscall_breakdown: HashMap<String, u64>,
    /// Map of resource types to utilization percentages
    pub resource_utilization: HashMap<String, f64>,
    /// Execution events with timestamps
    pub events: Vec<ExecutionEvent>,
}

impl Default for ExecutionMetrics {
    fn default() -> Self {
        Self {
            start_time: chrono::Utc::now(),
            duration_ms: 0,
            peak_memory_bytes: 0,
            avg_cpu_usage: 0.0,
            max_cpu_usage: 0.0,
            io_bytes_read: 0,
            io_bytes_written: 0,
            context_switches: 0,
            syscall_count: 0,
            syscall_breakdown: HashMap::new(),
            resource_utilization: HashMap::new(),
            events: Vec::new(),
        }
    }
}

/// Event representing important points in sandbox execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvent {
    /// Event timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Event type 
    pub event_type: EventType,
    /// Event message
    pub message: String,
    /// Additional event metadata
    pub metadata: HashMap<String, String>,
}

/// Types of execution events that can be tracked
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    /// Sandbox initialization started
    InitStart,
    /// Sandbox initialization completed
    InitComplete,
    /// Process execution started
    ExecutionStart,
    /// Process execution completed 
    ExecutionComplete,
    /// Resource limit warning (approaching limit)
    ResourceWarning,
    /// Resource limit violation (exceeding limit)
    ResourceViolation,
    /// Security violation detected
    SecurityViolation,
    /// Sandbox cleanup started
    CleanupStart, 
    /// Sandbox cleanup completed
    CleanupComplete,
    /// Generic event for custom use
    Custom(String),
}

/// Observer for monitoring sandbox execution and collecting metrics
pub struct SandboxObserver {
    /// Process ID being monitored
    process_id: Option<u32>,
    /// Start time of monitoring
    start_time: Instant,
    /// Collected metrics
    metrics: Arc<Mutex<ExecutionMetrics>>,
    /// Sampling interval for resource usage
    sampling_interval: Duration,
    /// Last sampling time
    last_sample_time: Instant,
    /// Whether monitoring is active
    active: bool,
}

impl SandboxObserver {
    /// Create a new sandbox observer
    pub fn new(sampling_interval_ms: u64) -> Self {
        let sampling_interval = Duration::from_millis(sampling_interval_ms);
        Self {
            process_id: None,
            start_time: Instant::now(),
            metrics: Arc::new(Mutex::new(ExecutionMetrics::default())),
            sampling_interval,
            last_sample_time: Instant::now(),
            active: false,
        }
    }

    /// Start monitoring a process
    pub fn start_monitoring(&mut self, pid: u32) -> Result<()> {
        info!("Starting monitoring for process {}", pid);
        self.process_id = Some(pid);
        self.start_time = Instant::now();
        self.last_sample_time = Instant::now();
        
        // Record initial event
        self.record_event(EventType::InitStart, "Started sandbox monitoring".to_string(), HashMap::new());
        
        self.active = true;
        Ok(())
    }

    /// Stop monitoring and finalize metrics
    pub fn stop_monitoring(&mut self) -> Result<ExecutionMetrics> {
        if !self.active {
            return Err(anyhow!("Monitoring is not active"));
        }
        
        info!("Stopping monitoring");
        self.active = false;
        
        // Record final event
        self.record_event(EventType::CleanupComplete, "Completed sandbox monitoring".to_string(), HashMap::new());
        
        // Finalize metrics
        let mut metrics = self.metrics.lock().unwrap();
        metrics.duration_ms = self.start_time.elapsed().as_millis() as u64;
        
        // Clone the metrics for return
        Ok(metrics.clone())
    }

    /// Sample current resource usage
    #[instrument(skip(self), level = "debug")]
    pub fn sample_resource_usage(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_sample_time);
        
        // Only sample at the configured interval
        if elapsed < self.sampling_interval {
            return Ok(());
        }
        
        self.last_sample_time = now;
        
        if let Some(pid) = self.process_id {
            #[cfg(all(feature = "linux", target_os = "linux"))]
            {
                self.sample_linux_process_metrics(pid)?;
            }
            
            #[cfg(not(all(feature = "linux", target_os = "linux")))]
            {
                debug!("Process resource sampling not available on this platform");
            }
        }
        
        Ok(())
    }

    /// Record an execution event
    pub fn record_event(&self, event_type: EventType, message: String, metadata: HashMap<String, String>) {
        if !self.active {
            return;
        }
        
        let event = ExecutionEvent {
            timestamp: chrono::Utc::now(),
            event_type,
            message,
            metadata,
        };
        
        let mut metrics = self.metrics.lock().unwrap();
        metrics.events.push(event);
    }

    /// Get a clone of the current metrics
    pub fn get_current_metrics(&self) -> ExecutionMetrics {
        self.metrics.lock().unwrap().clone()
    }

    /// Check if any resource limits are being approached
    pub fn check_resource_warnings(&self) -> Vec<(String, f64)> {
        let metrics = self.metrics.lock().unwrap();
        let mut warnings = Vec::new();
        
        // Example: Check if memory usage is above 80% of limit
        if let Some(utilization) = metrics.resource_utilization.get("memory") {
            if *utilization > 80.0 {
                warnings.push(("memory".to_string(), *utilization));
            }
        }
        
        // Example: Check if CPU usage is above 80% of limit
        if let Some(utilization) = metrics.resource_utilization.get("cpu") {
            if *utilization > 80.0 {
                warnings.push(("cpu".to_string(), *utilization));
            }
        }
        
        warnings
    }
}

/// Implementation for Linux-specific process metrics sampling
#[cfg(all(feature = "linux", target_os = "linux"))]
impl SandboxObserver {
    fn sample_linux_process_metrics(&mut self, pid: u32) -> Result<()> {
        // Get process info using procfs
        let process = Process::new(pid as i32)
            .map_err(|e| anyhow!("Failed to access process {}: {}", pid, e))?;
        
        // Get process statistics
        let stat = process.stat()
            .map_err(|e| anyhow!("Failed to get process stats: {}", e))?;
        
        // Get memory info
        let mem_info = process.statm()
            .map_err(|e| anyhow!("Failed to get process memory stats: {}", e))?;
        
        // Get I/O info
        let io_info = process.io()
            .map_err(|e| anyhow!("Failed to get process I/O stats: {}", e))
            .unwrap_or_default();
        
        let mut metrics = self.metrics.lock().unwrap();
        
        // Update memory metrics (resident set size in bytes)
        let memory_bytes = mem_info.resident * page_size::get();
        metrics.peak_memory_bytes = metrics.peak_memory_bytes.max(memory_bytes as u64);
        
        // Update CPU metrics
        // Simple CPU usage calculation - this could be improved
        let cpu_time = (stat.utime + stat.stime) as f64 / 100.0; // In seconds
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let cpu_usage = if elapsed > 0.0 { (cpu_time / elapsed) * 100.0 } else { 0.0 };
        
        // Update max CPU usage
        metrics.max_cpu_usage = metrics.max_cpu_usage.max(cpu_usage);
        
        // Update average CPU usage (simple running average)
        if metrics.avg_cpu_usage == 0.0 {
            metrics.avg_cpu_usage = cpu_usage;
        } else {
            metrics.avg_cpu_usage = (metrics.avg_cpu_usage + cpu_usage) / 2.0;
        }
        
        // Update I/O metrics
        metrics.io_bytes_read = io_info.read_bytes;
        metrics.io_bytes_written = io_info.write_bytes;
        
        // Update context switches
        metrics.context_switches = (stat.voluntary_ctxt_switches + stat.nonvoluntary_ctxt_switches) as u64;
        
        // Update resource utilization map
        metrics.resource_utilization.insert("memory".to_string(), 0.0); // Would need to compare against limits
        metrics.resource_utilization.insert("cpu".to_string(), cpu_usage);
        
        debug!("Sampled process metrics: mem={} bytes, cpu={:.1}%", 
               memory_bytes, cpu_usage);
        
        Ok(())
    }
}

/// Generate a summary report from execution metrics
pub fn generate_report(metrics: &ExecutionMetrics) -> String {
    let mut report = String::new();
    
    report.push_str(&format!("# Sandbox Execution Report\n\n"));
    report.push_str(&format!("Execution started: {}\n", metrics.start_time));
    report.push_str(&format!("Duration: {} ms\n", metrics.duration_ms));
    report.push_str(&format!("Peak memory usage: {} bytes ({:.2} MB)\n", 
                             metrics.peak_memory_bytes,
                             metrics.peak_memory_bytes as f64 / (1024.0 * 1024.0)));
    report.push_str(&format!("CPU usage: {:.2}% avg, {:.2}% max\n", 
                             metrics.avg_cpu_usage, 
                             metrics.max_cpu_usage));
    report.push_str(&format!("I/O: {} bytes read, {} bytes written\n", 
                             metrics.io_bytes_read, 
                             metrics.io_bytes_written));
    report.push_str(&format!("Context switches: {}\n", metrics.context_switches));
    
    // Add events timeline
    report.push_str("\n## Execution Timeline\n\n");
    for event in &metrics.events {
        report.push_str(&format!("- [{}] {}: {}\n", 
                                 event.timestamp.format("%H:%M:%S%.3f"),
                                 format!("{:?}", event.event_type),
                                 event.message));
    }
    
    report
}

/// Serialize metrics to JSON
pub fn metrics_to_json(metrics: &ExecutionMetrics) -> Result<String> {
    serde_json::to_string_pretty(metrics)
        .map_err(|e| anyhow!("Failed to serialize metrics to JSON: {}", e))
} 