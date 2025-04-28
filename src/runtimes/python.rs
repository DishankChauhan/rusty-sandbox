use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::path::Path;
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::runtime::{RuntimeExecutor, SandboxPolicy, ExecutionResult};
use crate::linter;
use crate::sandbox;

pub struct PythonExecutor;

impl PythonExecutor {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl RuntimeExecutor for PythonExecutor {
    fn name(&self) -> &'static str {
        "python"
    }
    
    fn supported_extensions(&self) -> &[&'static str] {
        &["py"]
    }
    
    fn lint_code(&self, content: &str) -> Result<()> {
        // Reuse existing linter functionality for Python
        linter::check_for_dangerous_code(content, sandbox::FileType::Python)
    }
    
    async fn execute(&self, file_path: &Path, policy: &SandboxPolicy) -> Result<ExecutionResult> {
        info!("PythonExecutor: Executing file {:?}", file_path);
        
        // Convert policy to SandboxConfig
        let config = sandbox::SandboxConfig {
            file_path: file_path.to_path_buf(),
            file_type: sandbox::FileType::Python,
            memory_limit_mb: policy.memory_limit_mb,
            cpu_time_limit_s: policy.cpu_time_limit_s,
            timeout_s: policy.timeout_s,
        };
        
        // Track execution time
        let start_time = Instant::now();
        
        // Run in sandbox using existing functionality
        let result = sandbox::run_sandboxed(config).await?;
        
        // Convert to ExecutionResult
        Ok(ExecutionResult {
            stdout: result.stdout,
            stderr: result.stderr,
            exit_status: result.exit_status,
            execution_time: start_time.elapsed(),
            peak_memory_kb: result.peak_memory_kb,
            resource_metrics: None,
        })
    }
} 