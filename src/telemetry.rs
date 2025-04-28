use anyhow::{anyhow, Result};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use log::info;
use crate::resources::ResourceMetrics;

// Metric names
const METRIC_CPU_USAGE: &str = "rusty_sandbox.cpu_usage";
const METRIC_MEMORY_USAGE: &str = "rusty_sandbox.memory_usage";
const METRIC_EXECUTION_TIME: &str = "rusty_sandbox.execution_time";
const METRIC_EXECUTION_COUNT: &str = "rusty_sandbox.executions";
const METRIC_ERROR_COUNT: &str = "rusty_sandbox.errors";
const METRIC_SECURITY_BREACHES: &str = "rusty_sandbox.security_breaches";
const METRIC_SANDBOX_TIMEOUTS: &str = "rusty_sandbox.timeouts";
const METRIC_SANDBOX_RESOURCE_LIMITS: &str = "rusty_sandbox.resource_limits_exceeded";

// Span names
const SPAN_SANDBOX_EXECUTION: &str = "sandbox.execute";
const SPAN_PROCESS_SPAWN: &str = "sandbox.process.spawn";
const SPAN_RESOURCE_MONITOR: &str = "resource_monitor";
const SPAN_WATCHDOG: &str = "watchdog_check";

/// Security event for telemetry
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub event_type: String,
    pub severity: String,
    pub description: String,
    pub process_id: Option<u32>,
    pub timestamp: u64,
    pub additional_data: HashMap<String, String>,
}

// Global telemetry manager instance
lazy_static::lazy_static! {
    static ref TELEMETRY_MANAGER: Mutex<Option<TelemetryManager>> = Mutex::new(None);
}

/// Telemetry manager for the sandbox
pub struct TelemetryManager {
    // Security events for alerting
    security_events: Arc<Mutex<Vec<SecurityEvent>>>,
    
    // Alert thresholds
    cpu_alert_threshold: f64,
    memory_alert_threshold: f64,
    
    // Simple counters for metrics
    cpu_usage: Arc<Mutex<Vec<f64>>>,
    memory_usage: Arc<Mutex<Vec<f64>>>,
    execution_time: Arc<Mutex<Vec<f64>>>,
    execution_count: Arc<Mutex<u64>>,
    error_count: Arc<Mutex<u64>>,
    breach_count: Arc<Mutex<u64>>,
    timeout_count: Arc<Mutex<u64>>,
    resource_limits_exceeded: Arc<Mutex<u64>>,
}

impl TelemetryManager {
    /// Initialize a simplified telemetry manager
    pub fn init(
        service_name: &str,
        cpu_alert_threshold: f64,
        memory_alert_threshold: f64,
    ) -> Result<()> {
        let mut manager = TELEMETRY_MANAGER.lock().unwrap();
        
        // Check if already initialized
        if manager.is_some() {
            return Ok(());
        }
        
        info!("Initializing telemetry for {}", service_name);
        
        // Create a simple telemetry manager
        *manager = Some(TelemetryManager {
            security_events: Arc::new(Mutex::new(Vec::new())),
            cpu_alert_threshold,
            memory_alert_threshold,
            cpu_usage: Arc::new(Mutex::new(Vec::new())),
            memory_usage: Arc::new(Mutex::new(Vec::new())),
            execution_time: Arc::new(Mutex::new(Vec::new())),
            execution_count: Arc::new(Mutex::new(0)),
            error_count: Arc::new(Mutex::new(0)),
            breach_count: Arc::new(Mutex::new(0)),
            timeout_count: Arc::new(Mutex::new(0)),
            resource_limits_exceeded: Arc::new(Mutex::new(0)),
        });
        
        Ok(())
    }

    /// Get a reference to the global telemetry manager
    pub fn global() -> Result<TelemetryManager> {
        let guard = TELEMETRY_MANAGER.lock().unwrap();
        
        if let Some(ref manager) = *guard {
            Ok(manager.clone())
        } else {
            Err(anyhow!("TelemetryManager not initialized"))
        }
    }
    
    /// Begin a new sandbox execution span with the given execution ID
    pub fn start_execution_span(&self, execution_id: &str) {
        info!("Starting execution span: {}", execution_id);
    }
    
    /// Create a span for process spawn operations
    pub fn start_process_span(&self, command: &str, pid: Option<u32>) {
        info!("Process spawn: {} (PID: {:?})", command, pid);
    }
    
    /// Record resource metrics from the resource monitor
    pub fn record_resource_metrics(&self, metrics: &ResourceMetrics) {
        // Record CPU usage
        if let Some(cpu) = metrics.cpu_usage {
            self.cpu_usage.lock().unwrap().push(cpu);
            
            // Check if we need to send an alert
            if cpu > self.cpu_alert_threshold {
                self.add_security_event(SecurityEvent {
                    event_type: "resource_warning".to_string(),
                    severity: "warning".to_string(),
                    description: format!("CPU usage at {:.1}% exceeds alert threshold of {:.1}%", 
                                        cpu, self.cpu_alert_threshold),
                    process_id: None,
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    additional_data: HashMap::new(),
                });
            }
        }
        
        // Record memory usage
        if let Some(memory) = metrics.memory_usage_percent {
            self.memory_usage.lock().unwrap().push(memory);
            
            // Check if we need to send an alert
            if memory > self.memory_alert_threshold {
                self.add_security_event(SecurityEvent {
                    event_type: "resource_warning".to_string(),
                    severity: "warning".to_string(),
                    description: format!("Memory usage at {:.1}% exceeds alert threshold of {:.1}%", 
                                         memory, self.memory_alert_threshold),
                    process_id: None,
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    additional_data: HashMap::new(),
                });
            }
        }
        
        // If limits exceeded, increment counter
        if metrics.limits_exceeded {
            let mut count = self.resource_limits_exceeded.lock().unwrap();
            *count += 1;
            
            // Add as security event
            self.add_security_event(SecurityEvent {
                event_type: "resource_limit_exceeded".to_string(),
                severity: "critical".to_string(),
                description: "Resource limits exceeded - sandbox terminating".to_string(),
                process_id: None,
                timestamp: chrono::Utc::now().timestamp() as u64,
                additional_data: HashMap::new(),
            });
        }
    }
    
    /// Record the execution time of a sandbox run
    pub fn record_execution_time(&self, time_ms: f64) {
        self.execution_time.lock().unwrap().push(time_ms);
    }
    
    /// Increment the execution counter
    pub fn record_execution(&self) {
        let mut count = self.execution_count.lock().unwrap();
        *count += 1;
    }
    
    /// Record an error occurrence
    pub fn record_error(&self, error_type: &str) {
        let mut count = self.error_count.lock().unwrap();
        *count += 1;
        
        // Log the error
        info!("Error recorded: {}", error_type);
    }
    
    /// Record a security breach
    pub fn record_breach(&self, breach_type: &str, description: &str, pid: Option<u32>) {
        let mut count = self.breach_count.lock().unwrap();
        *count += 1;
        
        // Add as critical security event
        self.add_security_event(SecurityEvent {
            event_type: "security_breach".to_string(),
            severity: "critical".to_string(),
            description: description.to_string(),
            process_id: pid,
            timestamp: chrono::Utc::now().timestamp() as u64,
            additional_data: {
                let mut data = HashMap::new();
                data.insert("breach_type".to_string(), breach_type.to_string());
                data
            },
        });
    }
    
    /// Record a timeout
    pub fn record_timeout(&self, timeout_secs: u64) {
        let mut count = self.timeout_count.lock().unwrap();
        *count += 1;
        
        // Add as security event
        self.add_security_event(SecurityEvent {
            event_type: "timeout".to_string(),
            severity: "error".to_string(),
            description: format!("Sandbox execution timed out after {} seconds", timeout_secs),
            process_id: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
            additional_data: HashMap::new(),
        });
    }
    
    /// Add a security event for alerting
    pub fn add_security_event(&self, event: SecurityEvent) {
        let mut events = self.security_events.lock().unwrap();
        events.push(event);
    }
    
    /// Get all security events, clearing the buffer
    pub fn get_and_clear_security_events(&self) -> Vec<SecurityEvent> {
        let mut events = self.security_events.lock().unwrap();
        std::mem::take(&mut *events)
    }
    
    /// Shutdown the telemetry system
    pub fn shutdown() -> Result<()> {
        // Nothing to do in simplified version
        Ok(())
    }
}

impl Clone for TelemetryManager {
    fn clone(&self) -> Self {
        Self {
            security_events: self.security_events.clone(),
            cpu_alert_threshold: self.cpu_alert_threshold,
            memory_alert_threshold: self.memory_alert_threshold,
            cpu_usage: self.cpu_usage.clone(),
            memory_usage: self.memory_usage.clone(),
            execution_time: self.execution_time.clone(),
            execution_count: self.execution_count.clone(),
            error_count: self.error_count.clone(),
            breach_count: self.breach_count.clone(),
            timeout_count: self.timeout_count.clone(),
            resource_limits_exceeded: self.resource_limits_exceeded.clone(),
        }
    }
} 