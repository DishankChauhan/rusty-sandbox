use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, warn, error};
use tokio::sync::mpsc;

mod sandbox;
mod linter;
mod resources;
mod runtime;
mod config;
mod runtimes;
mod security;
mod watchdog;
mod telemetry;
mod dashboard;
mod cgroups;

use runtime::{SandboxPolicy, RuntimeExecutor};
use crate::sandbox::SandboxConfig;
use security::{SecurityPolicy, SecurityLevel};
use telemetry::TelemetryManager;
use dashboard::{Dashboard, DashboardEvent};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to sandbox configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,
    
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
    
    /// Enable monitoring dashboard
    #[arg(short, long)]
    monitor: bool,
    
    /// Security level (basic, standard, enhanced, maximum)
    #[arg(long, default_value = "standard")]
    security: Option<String>,
    
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
    },
    
    /// List supported file types
    ListSupported,
    
    /// Run the monitoring dashboard in standalone mode
    Monitor {
        /// Process ID to monitor (optional)
        #[arg(short, long)]
        pid: Option<u32>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    setup_logging();
    
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Set up telemetry if not in minimal mode
    if !cli.verbose {
        if let Err(e) = TelemetryManager::init("rusty-sandbox", 80.0, 80.0) {
            warn!("Failed to initialize telemetry: {}", e);
        }
    }
    
    // Load configuration
    let config_path = cli.config.as_ref().map(|p| p.to_str().unwrap().to_string());
    
    // Load the sandbox configuration
    let sandbox_config = match config_path {
        Some(path) => config::load_config(path)?,
        None => config::default_config(),
    };
    
    // Parse security level
    let security_level = match cli.security.as_deref() {
        Some("basic") => SecurityLevel::Basic,
        Some("standard") => SecurityLevel::Standard,
        Some("enhanced") => SecurityLevel::Enhanced,
        Some("maximum") => SecurityLevel::Maximum,
        _ => SecurityLevel::Standard,
    };
    
    // Create security policy from security level
    let security_policy = SecurityPolicy::with_level(security_level);
    
    // Initialize the runtime registry with all available executors
    let registry = runtimes::init_registry();
    
    // Handle dashboard mode first if requested
    if cli.monitor {
        if let Commands::Monitor { pid } = cli.command {
            return run_dashboard(pid);
        }
    }
    
    match cli.command {
        Commands::Run { file, memory_limit, cpu_limit, timeout } => {
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
            let mut policy = sandbox_config.to_policy();
            
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
            if cli.verbose {
                println!("Verbose mode enabled");
            }
            
            // Launch dashboard if monitoring is enabled
            let dashboard_sender = if cli.monitor {
                Some(start_dashboard()?)
            } else {
                None
            };
            
            // Add language-specific options from config
            policy.language_options = sandbox_config.get_language_options(&file);
            
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
                    if cli.verbose {
                        println!("CPU time used: {:.2} seconds", result.execution_time.as_secs_f64());
                        if let Some(memory) = result.peak_memory_kb {
                            println!("Peak memory usage: {} KB", memory);
                        }
                    }
                    
                    // Send metrics to dashboard if monitoring
                    if let Some(sender) = &dashboard_sender {
                        if let Some(metrics) = result.resource_metrics {
                            let _ = sender.send(DashboardEvent::ResourceMetrics(metrics));
                        }
                    }
                    
                    // Record execution in telemetry
                    if let Ok(telemetry) = TelemetryManager::global() {
                        telemetry.record_execution();
                        telemetry.record_execution_time(result.execution_time.as_millis() as f64);
                    }
                }
                Err(e) => {
                    error!("Error running sandboxed code: {}", e);
                    eprintln!("Error running sandboxed code: {}", e);
                    
                    // Record error in telemetry
                    if let Ok(telemetry) = TelemetryManager::global() {
                        telemetry.record_error("execution_error");
                    }
                }
            }
        },
        
        Commands::ListSupported => {
            println!("Supported file types:");
            for extension in registry.list_supported_extensions() {
                println!("- .{}", extension);
            }
        },
        
        Commands::Monitor { pid } => {
            run_dashboard(pid)?;
        }
    }
    
    // Shutdown telemetry
    let _ = TelemetryManager::shutdown();
    
    Ok(())
}

/// Start the monitoring dashboard in a separate thread
fn start_dashboard() -> Result<tokio::sync::mpsc::Sender<DashboardEvent>> {
    let (sender, receiver) = tokio::sync::mpsc::channel(100);
    
    std::thread::spawn(move || {
        let mut dashboard = Dashboard::new();
        dashboard.init().expect("Failed to initialize dashboard");
        dashboard.run().expect("Failed to run dashboard");
    });
    
    Ok(sender)
}

/// Run the dashboard in standalone mode
fn run_dashboard(pid: Option<u32>) -> Result<()> {
    println!("Starting monitoring dashboard...");
    
    let mut dashboard = Dashboard::new();
    
    // Register process if provided
    if let Some(pid) = pid {
        let sender = dashboard.get_event_sender();
        let _ = sender.send(DashboardEvent::ProcessStarted(pid));
    }
    
    // Run dashboard until user exits
    dashboard.init()?;
    dashboard.run()?;
    
    Ok(())
}

fn setup_logging() {
    // Initialize the logger with a default configuration
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();
}
