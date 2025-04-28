use anyhow::{Result, anyhow, Context};
use async_trait::async_trait;
use std::path::Path;
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::io::Read;
use tracing::{info, warn, error};
use tokio::task;
use tokio::sync::mpsc;
use tokio::time;
use std::fs;

#[cfg(feature = "wasm")]
use wasmtime::{Engine, Module, Store, Config, Linker};
#[cfg(feature = "wasm")]
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder};
#[cfg(feature = "wasm")]
use wasi_common::WasiFile;
#[cfg(feature = "wasm")]
use wasi_common::pipe::{ReadPipe, WritePipe};
#[cfg(feature = "wasm")]
use std::sync::{Mutex, RwLock};
#[cfg(feature = "wasm")]
use std::future::Future;
#[cfg(feature = "wasm")]
use std::pin::Pin;
#[cfg(feature = "wasm")]
use wat;
#[cfg(feature = "wasm")]
use wasmtime::ResourceLimiterAsync;

use crate::runtime::{RuntimeExecutor, SandboxPolicy, ExecutionResult};

pub struct WasmExecutor;

impl WasmExecutor {
    pub fn new() -> Self {
        Self {}
    }
    
    // Helper to read WASM file content
    fn read_wasm_file(&self, file_path: &Path) -> Result<Vec<u8>> {
        fs::read(file_path).with_context(|| format!("Failed to read WASM file: {:?}", file_path))
    }
    
    // Helper to get WASM bytes from either binary .wasm or text .wat files
    #[cfg(feature = "wasm")]
    fn get_wasm_bytes(&self, file_path: &Path) -> Result<Vec<u8>> {
        let content = fs::read(file_path)?;
        
        // If this is a .wat file, convert it to binary WASM
        if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
            if ext == "wat" {
                info!("Converting WebAssembly Text Format to binary WASM");
                let result = wat::parse_bytes(&content)
                    .with_context(|| format!("Failed to parse WAT file: {:?}", file_path))?;
                return Ok(result.to_vec());
            }
        }
        
        // Otherwise, assume it's already binary WASM
        Ok(content)
    }
}

// Add a resource limiter for enforcing memory and CPU limits
#[cfg(feature = "wasm")]
struct SandboxResourceLimiter {
    memory_limit: usize,
    peak_memory: Arc<Mutex<u64>>,
    start_time: Instant,
    cpu_time_limit: Duration,
}

#[cfg(feature = "wasm")]
impl SandboxResourceLimiter {
    fn new(policy: &SandboxPolicy, peak_memory: Arc<Mutex<u64>>) -> Self {
        SandboxResourceLimiter {
            memory_limit: policy.memory_limit_kb * 1024, // Convert KB to bytes
            peak_memory,
            start_time: Instant::now(),
            cpu_time_limit: Duration::from_secs(policy.cpu_time_limit_s),
        }
    }
}

#[cfg(feature = "wasm")]
impl ResourceLimiterAsync for SandboxResourceLimiter {
    // Memory limit enforcement
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, wasmtime::ResourceLimiterAsync> {
        // Check if memory growth would exceed limit
        if desired > self.memory_limit {
            return Ok(false);
        }
        
        // Update peak memory usage
        let mut peak = self.peak_memory.lock().unwrap();
        *peak = (*peak).max(desired as u64);
        
        Ok(true)
    }
    
    // Table size enforcement
    fn table_growing(
        &mut self,
        _current: u32,
        _desired: u32,
        _maximum: Option<u32>,
    ) -> std::result::Result<bool, wasmtime::ResourceLimiterAsync> {
        // Default table size limiting - 10MB entries max
        // Prevent attacks using extremely large tables
        const MAX_TABLE_SIZE: u32 = 10_000_000;
        Ok(_desired <= MAX_TABLE_SIZE)
    }
    
    // CPU time limiting
    async fn async_yield(
        &mut self,
    ) -> std::result::Result<(), wasmtime::ResourceLimiterAsync> {
        // Check if CPU time limit has been exceeded
        if self.start_time.elapsed() > self.cpu_time_limit {
            return Err(anyhow!("CPU time limit exceeded").into());
        }
        
        // Yield to allow other tasks to run
        tokio::task::yield_now().await;
        Ok(())
    }
}

#[async_trait]
impl RuntimeExecutor for WasmExecutor {
    fn name(&self) -> &'static str {
        "wasm"
    }
    
    fn supported_extensions(&self) -> &[&'static str] {
        &["wasm", "wat"]
    }
    
    fn lint_code(&self, _content: &str) -> Result<()> {
        // WASM is binary, so traditional text-based linting doesn't apply
        // In a production system, we might analyze the binary format for dangerous imports
        Ok(())
    }
    
    async fn execute(&self, file_path: &Path, policy: &SandboxPolicy) -> Result<ExecutionResult> {
        info!("WasmExecutor: Executing file {:?}", file_path);
        
        let file_path = file_path.to_path_buf();
        let policy_clone = policy.clone();
        
        // Use tokio to run CPU-intensive WASM compilation/execution in a separate thread
        let (tx, mut rx) = mpsc::channel(1);
        
        // Track execution time
        let start_time = Instant::now();
        
        // Spawn task for WASM execution
        let task_handle = task::spawn_blocking(move || {
            let result = execute_wasm_file(&file_path, &policy_clone);
            // Send result back to the main task
            tx.blocking_send(result).ok();
        });
        
        // Set a timeout for the execution
        let timeout_duration = Duration::from_secs(policy.timeout_s);
        let execution_result = time::timeout(timeout_duration, async {
            match rx.recv().await {
                Some(result) => result,
                None => Err(anyhow!("WASM execution task terminated without returning a result")),
            }
        }).await;
        
        // Handle timeout or execution result
        match execution_result {
            Ok(result) => {
                match result {
                    Ok(mut exec_result) => {
                        // Update execution time
                        exec_result.execution_time = start_time.elapsed();
                        Ok(exec_result)
                    },
                    Err(err) => Err(err),
                }
            },
            Err(_) => {
                // Timeout occurred
                // Attempt to abort the task
                task_handle.abort();
                Err(anyhow!("WASM execution timed out after {} seconds", policy.timeout_s))
            }
        }
    }
}

// Actual WASM execution using Wasmtime
fn execute_wasm_file(file_path: &Path, policy: &SandboxPolicy) -> Result<ExecutionResult> {
    #[cfg(feature = "wasm")]
    {
        // Check if it's a WAT file and convert it to WASM if needed
        let wasm_bytes = if file_path.extension().and_then(|e| e.to_str()) == Some("wat") {
            info!("Converting WAT to WASM...");
            let wat_content = fs::read(file_path)?;
            let result = wat::parse_bytes(&wat_content)
                .with_context(|| format!("Failed to parse WAT file: {:?}", file_path))?;
            result.to_vec()
        } else {
            // Read WASM file directly
            fs::read(file_path)?
        };
        
        // Configure Wasmtime engine
        let mut config = Config::new();
        config.wasm_threads(false); // Disable threading for security
        config.wasm_reference_types(true);
        config.wasm_bulk_memory(true);
        
        // Enable fuel (instruction counting) for CPU limits
        config.consume_fuel(true);
        
        // Add module validation
        config.wasm_module_linking(false); // Disable module linking for security
        config.strategy(wasmtime::Strategy::Cranelift); // Use Cranelift for better security validation
        
        // Create memory buffer for stdout/stderr capture
        let stdout = Arc::new(RwLock::new(Vec::new()));
        let stderr = Arc::new(RwLock::new(Vec::new()));
        
        let stdout_write = WritePipe::from_shared(stdout.clone());
        let stderr_write = WritePipe::from_shared(stderr.clone());
        
        // Create engine
        let engine = Engine::new(&config)?;
        
        // Create WASI context
        let mut wasi_builder = WasiCtxBuilder::new();
        
        // Track memory usage
        let peak_memory = Arc::new(Mutex::new(0u64));
        
        // Setup stdio
        wasi_builder = wasi_builder
            .stdout(Box::new(stdout_write))
            .stderr(Box::new(stderr_write))
            .inherit_stdin();
            
        // Set up environment access based on security policy
        if policy.enable_network {
            // In newer wasmtime, network access is managed differently
            wasi_builder = wasi_builder.inherit_env()?;
        }
        
        // Map allowed paths to WASI
        for path in &policy.allowed_paths {
            let canonical_path = std::fs::canonicalize(path)
                .with_context(|| format!("Failed to canonicalize path: {}", path))?;
                
            if canonical_path.exists() {
                let guest_path = format!("/{}", canonical_path.file_name().unwrap_or_default().to_string_lossy());
                
                // Create directory handle with cap-std
                use cap_std::fs::Dir;
                let dir = Dir::open_ambient_dir(&canonical_path, cap_std::ambient_authority())?;
                
                wasi_builder = wasi_builder.preopened_dir(dir, guest_path)?;
            }
        }
        
        let wasi = wasi_builder.build();
        
        // WASM module validation
        // Validate the WASM module for dangerous imports
        // This checks for potentially harmful imports before execution
        validate_wasm_module(&wasm_bytes)?;
        
        // Compile WASM module
        let module = Module::new(&engine, &wasm_bytes)?;
        
        // Create store with resource limiter
        let limiter = SandboxResourceLimiter::new(policy, peak_memory.clone());
        let mut store = Store::new(&engine, (wasi, limiter));
        
        // Set fuel (instruction limit) for the store based on CPU time limit
        // Each unit of fuel represents one wasm instruction
        // We use a heuristic of ~1B instructions per second on modern hardware
        let fuel_amount = policy.cpu_time_limit_s as u64 * 1_000_000_000;
        store.add_fuel(fuel_amount)?;
        
        // Create linker and add WASI imports
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s| s)?;
        
        // Execute module
        let start_time = Instant::now();
        
        // Instantiate the module and try to call the start function
        let instance = linker.instantiate(&mut store, &module)?;
        
        // Find the entry point - try _start first (WASI convention)
        let result = if let Some(start) = instance.get_func(&mut store, "_start") {
            // Execute the _start function
            match start.call(&mut store, &[], &mut []) {
                Ok(_) => {
                    // Success
                    let stdout_content = String::from_utf8_lossy(&stdout.read().unwrap()).to_string();
                    let stderr_content = String::from_utf8_lossy(&stderr.read().unwrap()).to_string();
                    
                    Ok(ExecutionResult {
                        stdout: stdout_content,
                        stderr: stderr_content,
                        exit_status: 0,
                        execution_time: start_time.elapsed(),
                        peak_memory_kb: Some(*peak_memory.lock().unwrap() / 1024),
                    })
                }
                Err(trap) => {
                    // Execution trapped
                    let stdout_content = String::from_utf8_lossy(&stdout.read().unwrap()).to_string();
                    let stderr_content = String::from_utf8_lossy(&stderr.read().unwrap()).to_string();
                    
                    let mut full_stderr = stderr_content;
                    if !full_stderr.is_empty() {
                        full_stderr.push_str("\n");
                    }
                    full_stderr.push_str(&format!("WASM execution error: {}", trap));
                    
                    Ok(ExecutionResult {
                        stdout: stdout_content,
                        stderr: full_stderr,
                        exit_status: 1,
                        execution_time: start_time.elapsed(),
                        peak_memory_kb: Some(*peak_memory.lock().unwrap() / 1024),
                    })
                }
            }
        } else if let Some(main) = instance.get_func(&mut store, "main") {
            // Try calling a "main" function instead
            match main.call(&mut store, &[], &mut []) {
                Ok(_) => {
                    let stdout_content = String::from_utf8_lossy(&stdout.read().unwrap()).to_string();
                    let stderr_content = String::from_utf8_lossy(&stderr.read().unwrap()).to_string();
                    
                    Ok(ExecutionResult {
                        stdout: stdout_content,
                        stderr: stderr_content,
                        exit_status: 0,
                        execution_time: start_time.elapsed(),
                        peak_memory_kb: Some(*peak_memory.lock().unwrap() / 1024),
                    })
                }
                Err(trap) => {
                    let stdout_content = String::from_utf8_lossy(&stdout.read().unwrap()).to_string();
                    let stderr_content = String::from_utf8_lossy(&stderr.read().unwrap()).to_string();
                    
                    let mut full_stderr = stderr_content;
                    if !full_stderr.is_empty() {
                        full_stderr.push_str("\n");
                    }
                    full_stderr.push_str(&format!("WASM execution error: {}", trap));
                    
                    Ok(ExecutionResult {
                        stdout: stdout_content,
                        stderr: full_stderr,
                        exit_status: 1,
                        execution_time: start_time.elapsed(),
                        peak_memory_kb: Some(*peak_memory.lock().unwrap() / 1024),
                    })
                }
            }
        } else {
            // No entry point found
            Err(anyhow!("No _start or main function found in WASM module"))
        };
        
        result
    }
    
    #[cfg(not(feature = "wasm"))]
    {
        // When WASM support is not compiled in, return an appropriate error
        Err(anyhow!("WASM support is not enabled. Rebuild with the 'wasm' feature."))
    }
}

// Add WASM module validation function
#[cfg(feature = "wasm")]
fn validate_wasm_module(wasm_bytes: &[u8]) -> Result<()> {
    use wasmtime::*;
    
    // Check if the binary format is valid
    if !wasmparser::validate(wasm_bytes, None).is_ok() {
        return Err(anyhow!("Invalid WASM module format"));
    }
    
    // Parse the module to check for dangerous imports
    let mut validator = wasmparser::Validator::new();
    let mut parser = wasmparser::Parser::new(0);
    
    // Dangerous import namespaces to check for
    let dangerous_namespaces = [
        "wasi_unstable",
        "env", // External environment access
        "host", // Host function access
    ];
    
    // Dangerous function names to check for
    let dangerous_functions = [
        "fd_write", // File descriptor write
        "fd_read",  // File descriptor read
        "proc_exit", // Process termination
        "environ_get", // Environment variables
        "environ_sizes_get", // Environment sizes
        "path_open", // File system access
    ];
    
    let mut payload_iter = parser.parse_all(wasm_bytes);
    while let Some(payload) = payload_iter.next() {
        match validator.validate(&payload?) {
            Ok(_) => {
                // Check for dangerous imports in Import sections
                if let wasmparser::Payload::ImportSection(imports) = payload? {
                    for import in imports {
                        let import = import?;
                        
                        // Check if the module namespace is in our dangerous list
                        if dangerous_namespaces.contains(&import.module) {
                            // For dangerous namespaces, check if function is also dangerous
                            if dangerous_functions.contains(&import.name) {
                                // Log the dangerous import but don't block it
                                // We rely on WASI's security model to handle permissions
                                warn!(
                                    "WASM module has potentially dangerous import: {}.{}", 
                                    import.module, 
                                    import.name
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => return Err(anyhow!("WASM module validation failed: {}", e)),
        }
    }
    
    Ok(())
}

// Notes for implementing actual WASM support:
// 
// 1. Add these dependencies to Cargo.toml:
//    wasmtime = "15.0.0"
//    wasmtime-wasi = "15.0.0"
//    wasi-common = "15.0.0"
//
// 2. Implement memory and CPU limiting using Wasmtime's resource limiting features
//
// 3. Setup a proper WASI context with controlled filesystem access
//
// 4. Use STDIN/STDOUT/STDERR capture through Memory/VirtualFiles 