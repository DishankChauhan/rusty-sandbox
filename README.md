# Rusty Sandbox

Rusty Sandbox is a secure code execution environment implemented in Rust. It allows for isolated execution of untrusted code in multiple languages including Python, JavaScript, and WebAssembly.

## Features

### Phase 1: Core Sandboxing
- Secure execution environment for untrusted code
- Support for multiple languages:
  - Python
  - JavaScript
  - WebAssembly
- Resource limiting (CPU, memory, execution time)
- Static code analysis to prevent malicious code execution
- Simple CLI interface

### Phase 2: Advanced Features 
- File system isolation
- Network access control
- Process isolation
- Enhanced security measures

### Phase 3: Monitoring and Telemetry
- Advanced resource monitoring
- Security breach detection
- Real-time telemetry
- Terminal-based monitoring dashboard
- Cross-platform support (Linux, macOS)

## Installation

### Prerequisites
- Rust 1.65+
- Python 3.6+ (for Python support)
- Node.js 16+ (for JavaScript support)
- WASM runtime (for WebAssembly support)

### Building from source
```bash
# Clone the repository
git clone https://github.com/DishankChauhan/rusty-sandbox.git
cd rusty-sandbox

# Build in release mode
cargo build --release

# Install (optional)
cargo install --path .
```

## Usage

### Basic usage
```bash
# Run a file in the sandbox
rusty-sandbox run file.py

# Set custom resource limits
rusty-sandbox run file.js --memory-limit 256 --cpu-limit 2 --timeout 5

# List supported file types
rusty-sandbox list-supported
```

### Configuration
Rusty Sandbox can be configured using a TOML configuration file:

```toml
# Example configuration file

[general]
working_dir = "./workspace"
tmp_dir = "./tmp"
log_level = "info"

[resource_limits]
memory_limit_mb = 512
cpu_time_limit_s = 5
timeout_s = 10
max_processes = 10
max_file_size_kb = 5120
max_open_files = 20

[security]
enable_network = false
allowed_paths = ["/tmp", "./workspace"]

[runtimes.python]
interpreter = "/usr/bin/python3"
packages_path = "./python_packages"

[runtimes.javascript]
interpreter = "/usr/bin/node"
modules_path = "./node_modules"

[runtimes.wasm]
enable_memory_growth = true
max_memory_pages = 100
```

## Security Features

### Static Analysis
Rusty Sandbox performs static analysis on code before execution to detect potentially dangerous operations:
- System command execution
- File operations outside allowed paths
- Network access
- Dangerous library imports
- Dynamic code evaluation

### Process Isolation
- Process limits and resource constraints
- Namespace isolation on Linux
- Strict file access controls
- Optional chroot jails

### Resource Limiting
- Memory usage limits
- CPU usage limits
- Execution timeouts
- File size and count limits
- Process count limits

### Security Monitoring
- Real-time security event monitoring
- Breach detection and alerting
- Comprehensive audit logs
- Process hierarchy verification

## Architecture

### Core Components
- **RuntimeExecutor Trait**: Interface for language-specific executors
- **RuntimeRegistry**: Manages available language executors
- **SandboxPolicy**: Defines resource limits and security settings
- **Watchdog Service**: Monitors sandbox integrity
- **Telemetry System**: Collects performance and security metrics
- **Dashboard**: Real-time monitoring UI

### Execution Flow
1. Code is submitted for execution
2. Static analysis checks for dangerous patterns
3. Appropriate runtime executor is selected
4. Sandbox environment is prepared
5. Resources are limited and security measures applied
6. Code is executed with watchdog monitoring
7. Results are returned with execution metrics
8. Resources are cleaned up

## Extending

### Adding new language support
To add support for a new language, implement the `RuntimeExecutor` trait and register the new executor with the `RuntimeRegistry`.

```rust
use crate::runtime::{RuntimeExecutor, SandboxPolicy, ExecutionResult};

pub struct MyLanguageExecutor;

#[async_trait]
impl RuntimeExecutor for MyLanguageExecutor {
    fn name(&self) -> &'static str {
        "mylanguage"
    }
    
    fn supported_extensions(&self) -> &[&'static str] {
        &["mylang"]
    }
    
    fn lint_code(&self, content: &str) -> Result<()> {
        // Implement linting for the language
    }
    
    async fn execute(&self, file_path: &Path, policy: &SandboxPolicy) -> Result<ExecutionResult> {
        // Implement execution logic
    }
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- This project is inspired by secure sandbox solutions like Firecracker, gVisor, and WASM sandboxes
- Thanks to the Rust community for providing excellent libraries for system programming