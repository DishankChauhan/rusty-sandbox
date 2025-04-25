# RustySandbox

A secure sandbox for executing untrusted code written in Rust.

## Overview

RustySandbox is a security-focused tool designed to safely execute untrusted code snippets. It isolates execution using Linux security features like namespaces, seccomp filters, and resource limits to prevent harmful system interactions.

### Current Features (Phase 1: MVP)

- Execute untrusted Python and JavaScript code securely through a CLI
- Isolate execution using Linux namespaces (process, network isolation)
- Limit resources (CPU, memory, processes, file size) using rlimit
- Restrict dangerous system calls using seccomp filters with a fine-grained policy
- Real-time resource monitoring with detailed usage statistics
- Static code analysis to detect potentially dangerous patterns
- Cross-platform compatibility with enhanced features on Linux
- Capture and report stdout, stderr, and exit status

## Prerequisites

- Linux operating system (for full security features)
- macOS or other platforms (basic functionality without isolation)
- Rust 1.56+ with Cargo
- Python 3.x and/or Node.js (depending on which code you want to execute)

⚠️ **IMPORTANT**: Security and resource limitation features vary significantly by platform. Please read the [Platform-Specific Notes](PLATFORM_NOTES.md) document for details about cross-platform differences.

## Building from Source

```bash
git clone https://github.com/yourusername/rusty-sandbox.git
cd rusty-sandbox
cargo build --release
```

The compiled binary will be in `./target/release/rusty-sandbox`.

## Usage

### Execute a Python file:

```bash
rusty-sandbox run path/to/file.py
```

### Execute a JavaScript file:

```bash
rusty-sandbox run path/to/file.js
```

### Set custom limits:

```bash
rusty-sandbox run path/to/file.py --memory-limit 256 --cpu-limit 3 --timeout 5
```

### Enable verbose output:

```bash
rusty-sandbox run path/to/file.py --verbose
```

## Platform-Specific Recommendations

For consistent behavior across different operating systems:

- **Linux**: Full security features available
- **macOS/Windows**: Set conservative memory limits (20% below actual requirement)

See [Platform-Specific Notes](PLATFORM_NOTES.md) for detailed recommendations.

## Security Features

- **Linux Namespaces**: Isolates processes using user, PID, network, mount, and IPC namespaces
- **Seccomp Filters**: Restricts system calls to a minimal safe set with BPF filtering
- **Resource Limits**: Prevents resource exhaustion attacks with:
  - Memory limits (both for Linux and language runtime specific)
  - CPU time constraints
  - Process count restrictions
  - File size limitations
  - Execution timeout enforcement
- **Static Analysis**: Detects potentially dangerous code patterns with regex-based linting
- **Temporary Execution**: All code runs in temporary isolated directories
- **Real-time Monitoring**: Tracks resource usage throughout execution

## Implementation Details

### Seccomp Filter Implementation
The sandbox implements a seccomp filter that allows only necessary system calls for code execution, blocking all potentially dangerous calls.

### Namespace Implementation
Multiple Linux namespaces are used to isolate the execution environment:
- User namespace for UID/GID mapping
- PID namespace for process isolation
- Network namespace to restrict network access
- Mount namespace for filesystem isolation
- IPC namespace for resource isolation

### Resource Monitoring
Real-time monitoring of:
- Memory usage (peak and average)
- CPU time (user and system)
- Execution time statistics

## Development Roadmap

### Phase 1: MVP (Completed)
- CLI tool for executing Python and JS snippets securely
- Basic resource constraints
- Process isolation
- Static code analysis
- Real-time resource monitoring

### Future Plans
- Enhanced seccomp profiles for different languages
- Support for more languages (Rust, Go, etc.)
- Network sandboxing with fine-grained control
- Web API for remote code execution
- Detailed resource usage metrics and visualization
- Containerization support via integration with Docker/OCI runtime

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.