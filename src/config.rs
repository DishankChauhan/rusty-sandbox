use anyhow::{Result, anyhow, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use log::debug;

use crate::runtime::SandboxPolicy;
use crate::sandbox::SandboxConfig;

/// The system configuration profile
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemProfile {
    /// Development profile with looser security and more debugging
    Development,
    /// Testing profile balancing security and usability
    Testing,
    /// Production profile with strict security
    Production,
    /// Custom profile with user-defined settings
    Custom(String),
}

impl Default for SystemProfile {
    fn default() -> Self {
        SystemProfile::Development
    }
}

/// The global configuration for Rusty Sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustyConfig {
    /// The active system profile
    pub profile: SystemProfile,
    
    /// Base directory for temporary files
    pub temp_dir: PathBuf,
    
    /// Default security level
    pub security_level: String,
    
    /// Enable telemetry collection
    pub enable_telemetry: bool,
    
    /// Maximum execution time in seconds
    pub max_execution_time: u64,
    
    /// Maximum memory usage in KB
    pub max_memory_kb: u64,
    
    /// Allow network access by default
    pub allow_network: bool,
    
    /// Allow subprocess creation by default
    pub allow_subprocesses: bool,
    
    /// Allowed filesystem paths
    pub allowed_paths: Vec<String>,
    
    /// Log verbosity level
    pub log_level: String,
    
    /// Language-specific configurations
    pub language_configs: std::collections::HashMap<String, LanguageConfig>,
}

/// Configuration for a specific language runtime
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageConfig {
    /// The language name
    pub name: String,
    
    /// Path to the language runtime
    pub runtime_path: Option<String>,
    
    /// Default arguments for the runtime
    pub default_args: Vec<String>,
    
    /// Maximum memory limit in KB
    pub memory_limit_kb: Option<u64>,
    
    /// CPU time limit in seconds
    pub cpu_time_limit_s: Option<u64>,
    
    /// Language-specific allowed paths
    pub allowed_paths: Option<Vec<String>>,
    
    /// Allow network access for this language
    pub allow_network: Option<bool>,
}

impl Default for RustyConfig {
    fn default() -> Self {
        RustyConfig {
            profile: SystemProfile::default(),
            temp_dir: PathBuf::from("/tmp/rusty-sandbox"),
            security_level: "standard".to_string(),
            enable_telemetry: true,
            max_execution_time: 30,
            max_memory_kb: 512 * 1024, // 512 MB
            allow_network: false,
            allow_subprocesses: false,
            allowed_paths: vec![
                "/tmp".to_string(),
                "/usr/lib".to_string(),
            ],
            log_level: "info".to_string(),
            language_configs: std::collections::HashMap::new(),
        }
    }
}

impl RustyConfig {
    /// Load configuration from a file
    pub fn load(config_path: &Path) -> Result<Self> {
        // Check if file exists
        if !config_path.exists() {
            info!("Config file not found at {:?}, using defaults", config_path);
            return Ok(Self::default());
        }
        
        // Read the file
        let config_str = fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config file: {:?}", config_path))?;
            
        // Parse the TOML
        let config: RustyConfig = toml::from_str(&config_str)
            .with_context(|| format!("Failed to parse config file: {:?}", config_path))?;
            
        Ok(config)
    }
    
    /// Save configuration to a file
    pub fn save(&self, config_path: &Path) -> Result<()> {
        // Create parent directories if they don't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }
        
        // Serialize to TOML
        let config_str = toml::to_string(self)
            .context("Failed to serialize config to TOML")?;
            
        // Write to file
        fs::write(config_path, config_str)
            .with_context(|| format!("Failed to write config to file: {:?}", config_path))?;
            
        Ok(())
    }
    
    /// Get the default config path
    pub fn default_path() -> PathBuf {
        if let Some(config_dir) = dirs::config_dir() {
            config_dir.join("rusty-sandbox").join("config.toml")
        } else {
            PathBuf::from("./config.toml")
        }
    }
    
    /// Apply the system profile settings
    pub fn apply_profile(&mut self) {
        match self.profile {
            SystemProfile::Development => {
                self.security_level = "basic".to_string();
                self.enable_telemetry = false;
                self.max_execution_time = 60;
                self.max_memory_kb = 1024 * 1024; // 1 GB
                self.allow_network = true;
                self.allow_subprocesses = true;
                self.log_level = "debug".to_string();
            },
            SystemProfile::Testing => {
                self.security_level = "standard".to_string();
                self.enable_telemetry = true;
                self.max_execution_time = 30;
                self.max_memory_kb = 512 * 1024; // 512 MB
                self.allow_network = true;
                self.allow_subprocesses = false;
                self.log_level = "info".to_string();
            },
            SystemProfile::Production => {
                self.security_level = "enhanced".to_string();
                self.enable_telemetry = true;
                self.max_execution_time = 15;
                self.max_memory_kb = 256 * 1024; // 256 MB
                self.allow_network = false;
                self.allow_subprocesses = false;
                self.log_level = "warn".to_string();
            },
            SystemProfile::Custom(_) => {
                // Custom profile keeps existing settings
                debug!("Using custom profile with current settings");
            }
        }
    }
    
    /// Get language configuration
    pub fn get_language_config(&self, language: &str) -> Option<&LanguageConfig> {
        self.language_configs.get(language)
    }
    
    /// Get the system profile name
    pub fn profile_name(&self) -> String {
        match &self.profile {
            SystemProfile::Development => "development".to_string(),
            SystemProfile::Testing => "testing".to_string(),
            SystemProfile::Production => "production".to_string(),
            SystemProfile::Custom(name) => name.clone(),
        }
    }
    
    /// Create a new configuration with the specified profile
    pub fn with_profile(profile: SystemProfile) -> Self {
        let mut config = Self::default();
        config.profile = profile;
        config.apply_profile();
        config
    }
}

/// Create default configurations for supported languages
pub fn create_default_language_configs() -> std::collections::HashMap<String, LanguageConfig> {
    let mut configs = std::collections::HashMap::new();
    
    // Python configuration
    configs.insert("python".to_string(), LanguageConfig {
        name: "python".to_string(),
        runtime_path: Some("/usr/bin/python3".to_string()),
        default_args: vec!["-u".to_string()], // Unbuffered output
        memory_limit_kb: Some(512 * 1024), // 512 MB
        cpu_time_limit_s: Some(15),
        allowed_paths: Some(vec![
            "/tmp".to_string(),
            "/usr/lib/python".to_string(),
            "/usr/local/lib/python".to_string(),
        ]),
        allow_network: Some(false),
    });
    
    // JavaScript configuration
    configs.insert("javascript".to_string(), LanguageConfig {
        name: "javascript".to_string(),
        runtime_path: Some("/usr/bin/node".to_string()),
        default_args: vec!["--no-warnings".to_string()],
        memory_limit_kb: Some(384 * 1024), // 384 MB
        cpu_time_limit_s: Some(12),
        allowed_paths: Some(vec![
            "/tmp".to_string(),
            "/usr/lib/node_modules".to_string(),
        ]),
        allow_network: Some(false),
    });
    
    // WebAssembly configuration
    configs.insert("wasm".to_string(), LanguageConfig {
        name: "wasm".to_string(),
        runtime_path: None, // Uses built-in runtime
        default_args: vec![],
        memory_limit_kb: Some(128 * 1024), // 128 MB
        cpu_time_limit_s: Some(8),
        allowed_paths: Some(vec![
            "/tmp".to_string(),
        ]),
        allow_network: Some(false),
    });
    
    configs
}

/// Initialize the configuration system
pub fn init_config() -> Result<RustyConfig> {
    let config_path = RustyConfig::default_path();
    
    // Try to load existing config
    let config = match RustyConfig::load(&config_path) {
        Ok(config) => {
            info!("Loaded configuration from {:?}", config_path);
            config
        },
        Err(e) => {
            warn!("Failed to load config: {}, using defaults", e);
            let mut config = RustyConfig::default();
            
            // Add default language configs
            config.language_configs = create_default_language_configs();
            
            // Try to save the default config for future use
            if let Err(e) = config.save(&config_path) {
                warn!("Failed to save default config: {}", e);
            } else {
                info!("Created default configuration at {:?}", config_path);
            }
            
            config
        }
    };
    
    Ok(config)
}

/// Get configuration for the specified profile
pub fn get_profile_config(profile_name: &str) -> Result<RustyConfig> {
    let profile = match profile_name.to_lowercase().as_str() {
        "dev" | "development" => SystemProfile::Development,
        "test" | "testing" => SystemProfile::Testing,
        "prod" | "production" => SystemProfile::Production,
        custom => SystemProfile::Custom(custom.to_string()),
    };
    
    let mut config = match RustyConfig::load(&RustyConfig::default_path()) {
        Ok(config) => config,
        Err(_) => RustyConfig::default(),
    };
    
    // Override the profile
    config.profile = profile;
    
    // Apply the profile settings
    config.apply_profile();
    
    Ok(config)
}

/// Load language-specific configuration
pub fn load_language_config(language: &str) -> Result<LanguageConfig> {
    let config = init_config()?;
    
    if let Some(lang_config) = config.get_language_config(language) {
        Ok(lang_config.clone())
    } else {
        // Create a default config for this language
        let default_configs = create_default_language_configs();
        
        if let Some(default_config) = default_configs.get(language) {
            Ok(default_config.clone())
        } else {
            // Generic default
            Ok(LanguageConfig {
                name: language.to_string(),
                runtime_path: None,
                default_args: vec![],
                memory_limit_kb: Some(256 * 1024), // 256 MB
                cpu_time_limit_s: Some(10),
                allowed_paths: Some(vec!["/tmp".to_string()]),
                allow_network: Some(false),
            })
        }
    }
}

/// Load configuration from a file
pub fn load_config(path: impl AsRef<Path>) -> Result<SandboxConfig> {
    let config_str = fs::read_to_string(path.as_ref())
        .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;
    
    let config: SandboxConfig = serde_json::from_str(&config_str)
        .with_context(|| "Failed to parse config file as JSON")?;
    
    Ok(config)
}

/// Create default configuration
pub fn default_config() -> SandboxConfig {
    SandboxConfig::default()
}

/// Save configuration to a file
pub fn save_config(config: &SandboxConfig, path: impl AsRef<Path>) -> Result<()> {
    let config_str = serde_json::to_string_pretty(config)
        .with_context(|| "Failed to serialize config to JSON")?;
    
    fs::write(path.as_ref(), config_str)
        .with_context(|| format!("Failed to write config to file: {:?}", path.as_ref()))?;
    
    Ok(())
} 