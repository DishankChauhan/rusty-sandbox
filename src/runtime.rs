use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::path::Path;
use std::time::Duration;
use std::collections::HashMap;

/// The ExecutionResult contains the output of running a file in a sandbox
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_status: i32,
    pub execution_time: Duration,
    pub peak_memory_kb: Option<u64>,
}

/// SandboxPolicy defines the resource limits and security settings
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    pub memory_limit_mb: u64,
    pub cpu_time_limit_s: u64,
    pub timeout_s: u64,
    pub max_processes: Option<u64>,
    pub max_file_size_kb: Option<u64>,
    pub max_open_files: Option<u64>,
    pub enable_network: bool,
    pub allowed_paths: Vec<String>,
    // Language-specific settings stored as string key-value pairs
    pub language_options: HashMap<String, String>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            memory_limit_mb: 512,
            cpu_time_limit_s: 5,
            timeout_s: 10,
            max_processes: Some(10),
            max_file_size_kb: Some(5 * 1024), // 5MB
            max_open_files: Some(20),
            enable_network: false,
            allowed_paths: vec![],
            language_options: HashMap::new(),
        }
    }
}

/// The RuntimeExecutor trait defines the interface for language-specific runtime implementations
#[async_trait]
pub trait RuntimeExecutor: Send + Sync {
    /// Returns the unique identifier for this runtime
    fn name(&self) -> &'static str;
    
    /// Returns the file extensions this runtime can handle
    fn supported_extensions(&self) -> &[&'static str];
    
    /// Checks if this runtime supports the given file
    fn supports_file(&self, file_path: &Path) -> bool {
        if let Some(extension) = file_path.extension() {
            if let Some(ext_str) = extension.to_str() {
                return self.supported_extensions().contains(&ext_str);
            }
        }
        false
    }
    
    /// Performs language-specific code linting/analysis
    fn lint_code(&self, content: &str) -> Result<()>;
    
    /// Executes the file in the sandbox
    async fn execute(&self, file_path: &Path, policy: &SandboxPolicy) -> Result<ExecutionResult>;
}

/// Registry for storing and retrieving RuntimeExecutors
pub struct RuntimeRegistry {
    executors: Vec<Box<dyn RuntimeExecutor>>,
}

impl RuntimeRegistry {
    pub fn new() -> Self {
        Self {
            executors: Vec::new(),
        }
    }
    
    pub fn register(&mut self, executor: Box<dyn RuntimeExecutor>) {
        self.executors.push(executor);
    }
    
    pub fn find_executor_for_file(&self, file_path: &Path) -> Option<&dyn RuntimeExecutor> {
        self.executors.iter()
            .find(|executor| executor.supports_file(file_path))
            .map(|boxed| boxed.as_ref())
    }
    
    pub fn get_executor_by_name(&self, name: &str) -> Option<&dyn RuntimeExecutor> {
        self.executors.iter()
            .find(|executor| executor.name() == name)
            .map(|boxed| boxed.as_ref())
    }
    
    pub fn list_supported_extensions(&self) -> Vec<&'static str> {
        let mut extensions = Vec::new();
        for executor in &self.executors {
            extensions.extend(executor.supported_extensions());
        }
        extensions
    }
} 