# RustySandbox Platform-Specific Notes

This document outlines important differences in RustySandbox behavior across different operating systems, with special attention to security and resource limitation features.

## Platform Capabilities Overview

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Memory Limits | Strong (kernel-enforced) | Moderate (application-level) | Moderate (application-level) |
| CPU Limits | Strong (kernel-enforced) | Moderate (timeout-based) | Moderate (timeout-based) |
| Process Isolation | Strong (namespaces) | Basic (subprocess) | Basic (subprocess) |
| System Call Filtering | Yes (seccomp) | No | No |
| Resource Monitoring | Detailed | Basic | Basic |

## Linux-Specific Features

On Linux, RustySandbox leverages several kernel-specific security features:

1. **Namespaces**: Uses PID, network, mount, and user namespaces for strong isolation
2. **Seccomp Filters**: Restricts allowed system calls to a minimal set
3. **Resource Limits**: Uses kernel-enforced limits for memory, CPU, file size, etc.
4. **Process Monitoring**: Uses /proc filesystem for precise resource tracking

⚠️ **Note**: These features require specific kernel configurations and capabilities. Some features may not work on older kernels or in certain containerized environments.

## macOS-Specific Considerations

⚠️ **WARNING**: Memory limits on macOS are NOT enforced by the kernel and can be exceeded under certain conditions!

On macOS, RustySandbox uses:

1. **PYTHONMEMORY Environment Variable**: Attempts to limit Python memory usage, but may not be strictly enforced
2. **Node.js --max-old-space-size**: For JavaScript memory limitations, but this is advisory
3. **Process Monitoring**: Periodically checks process memory usage and terminates processes exceeding limits
4. **Graceful Termination**: Attempts SIGTERM before SIGKILL when memory limits are exceeded

### Memory Limitation Behavior

Unlike Linux, where memory limits are strictly enforced by the kernel, macOS relies on:

1. Application-level cooperation (language runtimes respecting limits)
2. Active monitoring and termination when limits are detected as exceeded
3. More conservative memory allocation settings to account for runtime overhead

This means that short memory spikes may temporarily exceed your specified limits before the process is terminated.

## Windows-Specific Considerations

Similar to macOS, Windows lacks kernel-level resource enforcement mechanisms used on Linux, resulting in:

1. Limited process isolation
2. Advisory memory limits
3. Basic resource monitoring capabilities

## Cross-Platform Best Practices

For consistent behavior across platforms:

1. Set memory limits conservatively (at least 20% below actual intended limit)
2. Use timeout limits as your primary protection
3. Employ the linter to prevent risky code from executing in the first place
4. Test on each target platform before deploying

## Recommended Configuration by Platform

### Linux
```
rusty-sandbox run myfile.py --memory-limit 512 --cpu-limit 5 --timeout 10
```

### macOS & Windows
```
rusty-sandbox run myfile.py --memory-limit 400 --cpu-limit 5 --timeout 10
```

Note the lower memory limit recommendation for non-Linux platforms to account for the less precise enforcement mechanisms. 