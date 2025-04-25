use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, warn, error};

mod sandbox;
mod linter;
mod resources;
mod runtime;
mod config;
mod runtimes;

use runtime::{SandboxPolicy, RuntimeExecutor};
use config::SandboxConfig;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to sandbox configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a file in the sandbox
    Run {
        /// Path to the file to execute
        #[arg(required = true)]
        file: PathBuf,
        
        /// Memory limit in MB (overrides config)
        #[arg(long)]
        memory_limit: Option<u64>,
        
        /// CPU time limit in seconds (overrides config)
        #[arg(long)]
        cpu_limit: Option<u64>,
        
        /// Execution timeout in seconds (overrides config)
        #[arg(long)]
        timeout: Option<u64>,
        
        /// Enable verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// List supported file types
    ListSupported,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    setup_logging();
    
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Load configuration
    let config = match &cli.config {
        Some(path) => SandboxConfig::from_file(path)?,
        None => SandboxConfig::load()?,
    };
    
    // Initialize the runtime registry with all available executors
    let registry = runtimes::init_registry();
    
    match cli.command {
        Commands::Run { file, memory_limit, cpu_limit, timeout, verbose } => {
            println!("Running file: {:?}", file);
            
            // Check if file exists
            if !file.exists() {
                error!("File does not exist: {:?}", file);
                eprintln!("File does not exist: {:?}", file);
                return Ok(());
            }
            
            // Find appropriate executor for this file
            let executor = match registry.find_executor_for_file(&file) {
                Some(executor) => executor,
                None => {
                    let extensions = registry.list_supported_extensions();
                    error!("Unsupported file type. Supported extensions: {:?}", extensions);
                    eprintln!("Unsupported file type. Supported extensions: {:?}", extensions);
                    return Ok(());
                }
            };
            
            println!("Using executor: {}", executor.name());
            
            // Create a policy from config, with CLI overrides
            let mut policy = config.to_policy();
            
            // Apply CLI overrides
            if let Some(limit) = memory_limit {
                println!("Memory limit: {} MB (from CLI)", limit);
                policy.memory_limit_mb = limit;
            } else {
                println!("Memory limit: {} MB (from config)", policy.memory_limit_mb);
            }
            
            if let Some(limit) = cpu_limit {
                println!("CPU limit: {} seconds (from CLI)", limit);
                policy.cpu_time_limit_s = limit;
            } else {
                println!("CPU limit: {} seconds (from config)", policy.cpu_time_limit_s);
            }
            
            if let Some(limit) = timeout {
                println!("Timeout: {} seconds (from CLI)", limit);
                policy.timeout_s = limit;
            } else {
                println!("Timeout: {} seconds (from config)", policy.timeout_s);
            }
            
            // Set log level based on verbose flag
            if verbose {
                println!("Verbose mode enabled");
                // This would adjust log level in a real implementation
            }
            
            // Add language-specific options from config
            policy.language_options = config.get_language_options(&file);
            
            // Read file content for linting
            let content = match std::fs::read_to_string(&file) {
                Ok(content) => content,
                Err(e) => {
                    error!("Failed to read file: {}", e);
                    eprintln!("Failed to read file: {}", e);
                    return Ok(());
                }
            };
            
            // Lint the code before execution
            if let Err(e) = executor.lint_code(&content) {
                error!("Code linting failed: {}", e);
                eprintln!("Code linting failed: {}", e);
                return Ok(());
            }
            
            // Run the file in sandbox
            let start_time = std::time::Instant::now();
            match executor.execute(&file, &policy).await {
                Ok(result) => {
                    let elapsed = start_time.elapsed();
                    println!("Exit status: {}", result.exit_status);
                    println!("Stdout: {}", result.stdout);
                    if !result.stderr.is_empty() {
                        println!("Stderr: {}", result.stderr);
                    }
                    
                    // Display execution statistics
                    println!("\nExecution completed in {:.2} seconds", elapsed.as_secs_f64());
                    if verbose {
                        println!("CPU time used: {:.2} seconds", result.execution_time.as_secs_f64());
                        if let Some(memory) = result.peak_memory_kb {
                            println!("Peak memory usage: {} KB", memory);
                        }
                    }
                }
                Err(e) => {
                    error!("Error running sandboxed code: {}", e);
                    eprintln!("Error running sandboxed code: {}", e);
                }
            }
        },
        
        Commands::ListSupported => {
            println!("Supported file types:");
            for executor in &registry.list_supported_extensions() {
                println!("- .{}", executor);
            }
        }
    }
    
    Ok(())
}

fn setup_logging() {
    // Initialize the logger with a default configuration
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();
}
