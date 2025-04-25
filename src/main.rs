use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

mod sandbox;
mod linter;
mod resources;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
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
        
        /// Memory limit in MB
        #[arg(long, default_value = "512")]
        memory_limit: u64,
        
        /// CPU time limit in seconds
        #[arg(long, default_value = "5")]
        cpu_limit: u64,
        
        /// Execution timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,
        
        /// Enable verbose output
        #[arg(short, long)]
        verbose: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    setup_logging();
    
    // Parse command line arguments
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Run { file, memory_limit, cpu_limit, timeout, verbose } => {
            println!("Running file: {:?}", file);
            println!("Memory limit: {} MB", memory_limit);
            println!("CPU limit: {} seconds", cpu_limit);
            println!("Timeout: {} seconds", timeout);
            
            // Set log level based on verbose flag
            if verbose {
                println!("Verbose mode enabled");
                // This would adjust log level in a real implementation
            }
            
            // Determine file type by extension
            let file_type = match file.extension().and_then(|ext| ext.to_str()) {
                Some("py") => sandbox::FileType::Python,
                Some("js") => sandbox::FileType::JavaScript,
                _ => {
                    eprintln!("Unsupported file type. Currently supporting .py and .js files only");
                    return Ok(());
                }
            };
            
            // Check if file exists
            if !file.exists() {
                eprintln!("File does not exist: {:?}", file);
                return Ok(());
            }
            
            // Create sandbox config
            let config = sandbox::SandboxConfig {
                file_path: file.clone(),
                file_type,
                memory_limit_mb: memory_limit,
                cpu_time_limit_s: cpu_limit,
                timeout_s: timeout,
            };
            
            // Run the file in sandbox
            let start_time = std::time::Instant::now();
            match sandbox::run_sandboxed(config).await {
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
                    }
                }
                Err(e) => {
                    eprintln!("Error running sandboxed code: {}", e);
                }
            }
        }
    }
    
    Ok(())
}

fn setup_logging() {
    // Initialize the logger with a default configuration
    // This can be made more configurable later
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();
}
