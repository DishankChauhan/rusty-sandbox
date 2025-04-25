# 🛡️ Rusty Sandbox

A secure sandbox for executing untrusted code, implemented in Rust.

## 🚀 Features

- **Secure Execution**: Run untrusted code with strong isolation
- **Resource Limits**: Restrict memory, CPU, and file system usage
- **Multi-language Support**: Execute Python, JavaScript, and WebAssembly code
- **Plugin Architecture**: Easily extend with support for additional languages
- **Configuration System**: Customize sandbox behavior through a flexible configuration file

## 📋 Supported Languages

- **Python** (`.py` files)
- **JavaScript** (`.js` files)
- **WebAssembly** (`.wasm` files)

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/your-username/rusty-sandbox.git
cd rusty-sandbox

# Build the project
cargo build --release

# Install (optional)
cargo install --path .
```

## 🔧 Usage

### Basic Usage

```bash
# Run a Python file
rusty-sandbox run examples/hello.py

# Run a JavaScript file
rusty-sandbox run examples/hello.js

# Run a WebAssembly file
rusty-sandbox run examples/hello.wasm

# List supported file types
rusty-sandbox list-supported
```

### Custom Resource Limits

```bash
# Override memory limit (in MB)
rusty-sandbox run examples/hello.py --memory-limit 256

# Override CPU time limit (in seconds)
rusty-sandbox run examples/hello.py --cpu-limit 2

# Override execution timeout (in seconds)
rusty-sandbox run examples/hello.py --timeout 5
```

### Custom Configuration

```bash
# Use a custom configuration file
rusty-sandbox --config my-sandbox.toml run examples/hello.py
```

## ⚙️ Configuration

Rusty Sandbox uses a TOML configuration file (`sandbox.toml`) for customization. The configuration file can be placed in:

- Current directory (`./sandbox.toml`)
- Config directory (`./config/sandbox.toml`)
- User config directory (`~/.config/rusty-sandbox/sandbox.toml`)

### Example Configuration

```toml
# Rusty Sandbox Configuration

[general]
working_dir = "./workspace"
tmp_dir = "./tmp"
log_level = "info"

[resource_limits]
memory_limit_mb = 512
cpu_time_limit_s = 5
timeout_s = 10
max_processes = 10
max_file_size_kb = 5120  # 5MB
max_open_files = 20

[security]
enable_network = false
allowed_paths = [
    "./examples",
    "./workspace"
]

# Runtime-specific configurations
[runtimes.python]
interpreter = "python3"
extra_args = "--no-site-packages"

[runtimes.javascript]
runtime = "node"
extra_args = "--no-warnings"

[runtimes.wasm]
wasi_enabled = true
max_memory_pages = 100  # 6.4MB
```

## 🔌 Plugin Architecture

Rusty Sandbox uses a plugin-based architecture for language support. Each language is implemented as a `RuntimeExecutor` that can be registered with the system.

To add support for a new language:

1. Implement the `RuntimeExecutor` trait
2. Register the executor with the `RuntimeRegistry`
3. Add appropriate configurations to the `sandbox.toml` file

## 🔒 Security

Rusty Sandbox provides multiple layers of security:

- **Resource Limits**: Restrict memory usage, CPU time, file descriptors, etc.
- **Code Linting**: Detect potentially dangerous code patterns before execution
- **Sandboxing**: Use OS-level isolation mechanisms (seccomp, namespaces, etc. on Linux)
- **Execution Timeout**: Automatically terminate long-running processes
- **File System Isolation**: Restrict access to the file system

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Related Projects

- [Wasmtime](https://wasmtime.dev/) - Used for WebAssembly execution
- [Seccomp](https://en.wikipedia.org/wiki/Seccomp) - Linux kernel security feature for sandboxing
- [WASI](https://wasi.dev/) - WebAssembly System Interface