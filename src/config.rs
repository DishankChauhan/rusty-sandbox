use anyhow::{Result, anyhow, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::runtime::SandboxPolicy;

#[derive(Debug, Deserialize, Serialize)]
pub struct SandboxConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub resource_limits: ResourceLimitsConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub runtimes: RuntimeConfigs,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct GeneralConfig {
    #[serde(default = "default_working_dir")]
    pub working_dir: String,
    #[serde(default = "default_tmp_dir")]
    pub tmp_dir: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_working_dir() -> String {
    "./workspace".to_string()
}

fn default_tmp_dir() -> String {
    "./tmp".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct ResourceLimitsConfig {
    #[serde(default = "default_memory_limit")]
    pub memory_limit_mb: u64,
    #[serde(default = "default_cpu_limit")]
    pub cpu_time_limit_s: u64,
    #[serde(default = "default_timeout")]
    pub timeout_s: u64,
    #[serde(default = "default_max_processes")]
    pub max_processes: u64,
    #[serde(default = "default_max_file_size")]
    pub max_file_size_kb: u64,
    #[serde(default = "default_max_open_files")]
    pub max_open_files: u64,
}

fn default_memory_limit() -> u64 { 512 }
fn default_cpu_limit() -> u64 { 5 }
fn default_timeout() -> u64 { 10 }
fn default_max_processes() -> u64 { 10 }
fn default_max_file_size() -> u64 { 5 * 1024 } // 5MB
fn default_max_open_files() -> u64 { 20 }

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct SecurityConfig {
    #[serde(default = "default_enable_network")]
    pub enable_network: bool,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
}

fn default_enable_network() -> bool { false }

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct RuntimeConfigs {
    #[serde(default)]
    pub python: HashMap<String, String>,
    #[serde(default)]
    pub javascript: HashMap<String, String>,
    #[serde(default)]
    pub wasm: HashMap<String, String>,
    
    // Extension-to-runtime mappings
    #[serde(default)]
    pub extensions: HashMap<String, String>,
}

impl SandboxConfig {
    /// Load configuration from the specified file path
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;
        
        let config: SandboxConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {:?}", path))?;
        
        Ok(config)
    }
    
    /// Load configuration, searching in multiple locations
    pub fn load() -> Result<Self> {
        // Search paths in priority order
        let mut search_paths = vec![
            PathBuf::from("./sandbox.toml"),
            PathBuf::from("./config/sandbox.toml"),
        ];
        
        // Add config_dir path if available
        if let Some(config_dir) = dirs::config_dir() {
            search_paths.push(config_dir.join("rusty-sandbox/sandbox.toml"));
        }
        
        // Try each path
        for path in &search_paths {
            if path.exists() {
                info!("Loading configuration from {:?}", path);
                return Self::from_file(path);
            }
        }
        
        // No config found, use defaults
        warn!("No configuration file found, using defaults");
        Ok(Self::default())
    }
    
    /// Convert to a SandboxPolicy
    pub fn to_policy(&self) -> SandboxPolicy {
        SandboxPolicy {
            memory_limit_mb: self.resource_limits.memory_limit_mb,
            cpu_time_limit_s: self.resource_limits.cpu_time_limit_s,
            timeout_s: self.resource_limits.timeout_s,
            max_processes: Some(self.resource_limits.max_processes),
            max_file_size_kb: Some(self.resource_limits.max_file_size_kb),
            max_open_files: Some(self.resource_limits.max_open_files),
            enable_network: self.security.enable_network,
            allowed_paths: self.security.allowed_paths.clone(),
            language_options: HashMap::new(), // Will be filled based on file type
        }
    }
    
    /// Get language-specific options based on file extension
    pub fn get_language_options(&self, file_path: &Path) -> HashMap<String, String> {
        if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
            // Check if we have a custom runtime mapping for this extension
            if let Some(runtime) = self.runtimes.extensions.get(ext) {
                match runtime.as_str() {
                    "python" => return self.runtimes.python.clone(),
                    "javascript" => return self.runtimes.javascript.clone(),
                    "wasm" => return self.runtimes.wasm.clone(),
                    _ => {}
                }
            }
            
            // Default mapping based on extension
            match ext {
                "py" => return self.runtimes.python.clone(),
                "js" => return self.runtimes.javascript.clone(),
                "wasm" => return self.runtimes.wasm.clone(),
                _ => {}
            }
        }
        
        HashMap::new()
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            resource_limits: ResourceLimitsConfig::default(),
            security: SecurityConfig::default(),
            runtimes: RuntimeConfigs::default(),
        }
    }
} 