use anyhow::{anyhow, Result, Context};
use async_trait::async_trait;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Instant, Duration};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;
use log::debug;

use crate::runtime::{ExecutionResult, RuntimeExecutor, SandboxPolicy};
use crate::resources::ResourceMetrics;

/// C language runtime executor
pub struct CExecutor {
    /// Path to the gcc compiler
    compiler_path: PathBuf,
    /// Additional compiler flags
    compiler_flags: Vec<String>,
}

impl Default for CExecutor {
    fn default() -> Self {
        Self {
            compiler_path: PathBuf::from("/usr/bin/gcc"),
            compiler_flags: vec![
                "-Wall".to_string(),
                "-Wextra".to_string(),
                "-Werror".to_string(),
                "-std=c11".to_string(),
                "-O2".to_string(),
            ],
        }
    }
}

impl CExecutor {
    /// Create a new C executor with custom compiler path and flags
    pub fn new() -> Self {
        Self::default()
    }

    /// Compile C source code into an executable
    async fn compile_c(&self, source_path: &Path, output_path: &Path) -> Result<String> {
        // Ensure the compiler exists
        if !self.compiler_path.exists() {
            return Err(anyhow!("C compiler not found at {:?}", self.compiler_path));
        }

        // Build command to compile the C source
        let output = Command::new(&self.compiler_path)
            .args(&self.compiler_flags)
            .arg("-o")
            .arg(output_path)
            .arg(source_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute C compiler")?;

        // Check if compilation was successful
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(anyhow!("C compilation failed: {}", stderr));
        }

        // Return compiler output
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Ok(stderr)
    }
    
    /// Write content to a temporary file
    async fn write_to_temp_file(&self, content: &str) -> Result<tempfile::NamedTempFile> {
        let mut temp_file = tempfile::NamedTempFile::new()?;
        std::io::Write::write_all(&mut temp_file, content.as_bytes())?;
        Ok(temp_file)
    }
}

#[async_trait]
impl RuntimeExecutor for CExecutor {
    /// Returns the unique identifier for this runtime
    fn name(&self) -> &'static str {
        "c"
    }
    
    /// Returns the file extensions this runtime can handle
    fn supported_extensions(&self) -> &[&'static str] {
        &["c"]
    }

    /// Check if the executor supports the given file extension
    fn supports_file(&self, file_path: &Path) -> bool {
        file_path
            .extension()
            .and_then(OsStr::to_str)
            .map(|ext| ext == "c")
            .unwrap_or(false)
    }

    /// Lint the C source code
    fn lint_code(&self, content: &str) -> Result<()> {
        // Create a temporary file with the content
        let mut file = tempfile::NamedTempFile::new()?;
        std::io::Write::write_all(&mut file, content.as_bytes())?;

        // Use gcc's -fsyntax-only to check for syntax errors without compiling
        let output = Command::new(&self.compiler_path)
            .args(&["-fsyntax-only", "-Wall", "-Wextra"])
            .arg(file.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute C linter")?;
            
        // If compilation failed, return the error
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("C syntax check failed: {}", stderr));
        }

        Ok(())
    }

    /// Execute a C program with the given sandbox policy
    async fn execute(&self, file_path: &Path, policy: &SandboxPolicy) -> Result<ExecutionResult> {
        let start_time = Instant::now();
        
        // Check if the source file exists
        if !file_path.exists() {
            return Err(anyhow!("C source file not found: {:?}", file_path));
        }

        // Create a temporary directory for compilation output
        let temp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;
        let executable_path = temp_dir.path().join("program");

        // Compile the C source code
        let compile_output = self.compile_c(file_path, &executable_path).await?;
        debug!("C compilation result: {}", compile_output);

        // Make the executable actually executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&executable_path).await?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o755); // rwx for owner, rx for group and others
            fs::set_permissions(&executable_path, perms).await?;
        }

        // Prepare the command to run the executable
        let mut cmd = TokioCommand::new(&executable_path);
        
        // Set up standard I/O pipes
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Start the process
        let mut child = cmd.spawn().context("Failed to start C program")?;

        // Set up timeout for the process
        let timeout_duration = Duration::from_secs(policy.timeout_s);
        
        // Run the process with a timeout
        let status = match timeout(timeout_duration, child.wait()).await {
            Ok(result) => result.context("Failed to get exit status")?,
            Err(_) => {
                // Timeout reached, kill the process
                let _ = child.kill().await;
                return Ok(ExecutionResult {
                    stdout: String::new(),
                    stderr: "Process execution timed out".to_string(),
                    exit_status: -1,
                    execution_time: start_time.elapsed(),
                    peak_memory_kb: Some(0),
                    resource_metrics: None,
                });
            }
        };

        // Collect stdout and stderr
        let mut stdout = String::new();
        let mut stderr = String::new();

        if let Some(mut stdout_pipe) = child.stdout.take() {
            stdout_pipe.read_to_string(&mut stdout).await?;
        }

        if let Some(mut stderr_pipe) = child.stderr.take() {
            stderr_pipe.read_to_string(&mut stderr).await?;
        }

        // Return the execution result
        Ok(ExecutionResult {
            stdout,
            stderr,
            exit_status: status.code().unwrap_or(-1),
            execution_time: start_time.elapsed(),
            peak_memory_kb: Some(0), // We don't have memory metrics here
            resource_metrics: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;
    use std::time::Duration;
    use crate::runtime::RuntimeRegistry;

    #[tokio::test]
    async fn test_c_executor() {
        // Create a temporary C file
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            r#"
            #include <stdio.h>
            
            int main() {{
                printf("Hello, C world!\n");
                return 0;
            }}
            "#
        )
        .unwrap();

        // Create executor
        let executor = CExecutor::default();
        
        // Check that it supports .c files
        assert!(executor.supports_file(file.path()));
        
        // Create a basic sandbox policy
        let mut policy = SandboxPolicy::default();
        policy.timeout_s = 5;
        
        // Execute the program
        let result = executor.execute(file.path(), &policy).await.unwrap();
        
        // Verify the output
        assert_eq!(result.exit_status, 0);
        assert!(result.stdout.contains("Hello, C world!"));
    }
    
    #[tokio::test]
    async fn test_c_executor_timeout() {
        // Create a C program that runs forever
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            r#"
            #include <stdio.h>
            
            int main() {{
                printf("Starting infinite loop...\n");
                while(1) {{
                    // Infinite loop
                }}
                return 0;
            }}
            "#
        )
        .unwrap();
        
        // Create executor
        let executor = CExecutor::default();
        
        // Create a sandbox policy with a short timeout
        let mut policy = SandboxPolicy::default();
        policy.timeout_s = 1;
        
        // Execute the program
        let result = executor.execute(file.path(), &policy).await.unwrap();
        
        // Verify results
        assert_eq!(result.exit_status, -1);
        assert!(result.stderr.contains("timed out"));
    }
    
    #[tokio::test]
    async fn test_c_executor_with_registry() {
        // Create a registry and register our C executor
        let mut registry = RuntimeRegistry::new();
        registry.register(Box::new(CExecutor::default()));
        
        // Create a test file
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            r#"
            #include <stdio.h>
            
            int main() {{
                printf("Testing registry integration\n");
                return 42;  // Specific exit code for testing
            }}
            "#
        )
        .unwrap();
        
        // Check if the registry can handle .c files
        assert!(registry.supports_file(file.path()));
        
        // Create a sandbox policy
        let policy = SandboxPolicy::default();
        
        // Execute the program using the registry
        let result = registry.execute_file(file.path(), &policy, None).await.unwrap();
        
        // Verify results
        assert_eq!(result.exit_status, 42);
        assert!(result.stdout.contains("Testing registry integration"));
    }
} 