#!/bin/bash

# Enhanced test script for RustySandbox

# Build the project
echo "Building RustySandbox..."
cargo build

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

# Make the example files executable
chmod +x examples/*.py examples/*.js

# Create a test directory
mkdir -p test_output

# Run basic tests
echo -e "\n\n--- BASIC FUNCTIONALITY TESTS ---"

# Run the safe Python example
echo -e "\n\nRunning safe Python example:"
./target/debug/rusty-sandbox run examples/hello.py

# Run the dangerous Python example (this should be caught by the linter)
echo -e "\n\nRunning dangerous Python example (should be caught by linter):"
./target/debug/rusty-sandbox run examples/dangerous.py

# Run the JavaScript example
echo -e "\n\nRunning JavaScript example:"
./target/debug/rusty-sandbox run examples/hello.js

# Enhanced tests with resource limits
echo -e "\n\n--- RESOURCE LIMIT TESTS ---"

# Run with custom resource limits and verbose output
echo -e "\n\nRunning with custom resource limits (verbose):"
./target/debug/rusty-sandbox run examples/hello.py --memory-limit 256 --cpu-limit 3 --timeout 5 --verbose

# Create a CPU-intensive test
cat > test_output/cpu_intensive.py << EOF
#!/usr/bin/env python3
"""
A CPU-intensive example to test resource limits.
"""
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)

# Compute a large Fibonacci number (CPU-intensive)
result = fibonacci(35)
print(f"Fibonacci(35) = {result}")
EOF

chmod +x test_output/cpu_intensive.py

# Create a memory-intensive test
cat > test_output/memory_intensive.py << EOF
#!/usr/bin/env python3
"""
A memory-intensive example to test resource limits.
"""
# Try to allocate a large list in memory
try:
    # Attempt to allocate approximately 300MB
    large_list = [0] * (300 * 1024 * 1024 // 4)
    print(f"Allocated list of size {len(large_list)}")
except MemoryError:
    print("Memory allocation failed - limit working!")
EOF

chmod +x test_output/memory_intensive.py

# Run CPU-intensive test
echo -e "\n\nRunning CPU-intensive test with tight CPU limit (should hit limit or take a while):"
./target/debug/rusty-sandbox run test_output/cpu_intensive.py --cpu-limit 2 --verbose

# Run memory-intensive test
echo -e "\n\nRunning memory-intensive test with tight memory limit:"
./target/debug/rusty-sandbox run test_output/memory_intensive.py --memory-limit 100 --verbose

echo -e "\n\nAll tests complete!"

# Clean up
echo -e "Cleaning up test files..."
rm -rf test_output 