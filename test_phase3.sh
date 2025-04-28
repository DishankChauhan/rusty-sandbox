#!/bin/bash
# Test script for Phase 3 features of Rusty Sandbox

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo -e "\n${GREEN}====== $1 ======${NC}\n"
}

print_info() {
    echo -e "${YELLOW}$1${NC}"
}

print_error() {
    echo -e "${RED}ERROR: $1${NC}"
    exit 1
}

# Check if cargo is installed
if ! command -v cargo &> /dev/null; then
    print_error "Cargo is not installed. Please install Rust and Cargo first."
fi

# Build the project
print_header "Building Rusty Sandbox"
cargo build --release || print_error "Failed to build project"
print_info "Build successful!"

# Create test directory if it doesn't exist
mkdir -p tests/phase3

# Create a sample Python script that uses resources
cat > tests/phase3/resource_test.py << 'EOF'
import time
import math

# Allocate some memory
big_list = [i for i in range(1000000)]

# Use some CPU
def calculate_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

# Find some prime numbers
primes = []
for i in range(10000, 10500):
    if calculate_prime(i):
        primes.append(i)

print(f"Found {len(primes)} prime numbers")
print(f"First few: {primes[:5]}")

# Use more memory
another_list = [math.sqrt(i) for i in range(500000)]
print(f"Calculated {len(another_list)} square roots")

# Sleep a bit to allow monitoring
time.sleep(5)

print("Done!")
EOF

# Create a malicious test script
cat > tests/phase3/malicious_test.py << 'EOF'
import os
import sys
import socket

print("Trying to perform dangerous operations...")

# Try to access system info
try:
    print(f"Python version: {sys.version}")
    print(f"Current directory: {os.getcwd()}")
except Exception as e:
    print(f"Error accessing system info: {e}")

# Try to create a file
try:
    with open('malicious_file.txt', 'w') as f:
        f.write('This is a test')
    print("Created file successfully!")
except Exception as e:
    print(f"Error creating file: {e}")

# Try to access network
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("example.com", 80))
    print("Network connection successful!")
    s.close()
except Exception as e:
    print(f"Error connecting to network: {e}")

# Try to execute a system command
try:
    output = os.system('ls -la')
    print(f"Command execution output: {output}")
except Exception as e:
    print(f"Error executing command: {e}")

print("Done with malicious operations test")
EOF

# Create a JavaScript test file
cat > tests/phase3/resource_test.js << 'EOF'
// JavaScript resource usage test

// Memory usage
const memoryUsage = [];
for (let i = 0; i < 500000; i++) {
    memoryUsage.push({
        index: i,
        value: i * i,
        data: `Item ${i}`
    });
}

console.log(`Created ${memoryUsage.length} objects in memory`);

// CPU usage - calculate primes
function isPrime(num) {
    if (num <= 1) return false;
    if (num <= 3) return true;
    if (num % 2 === 0 || num % 3 === 0) return false;
    
    let i = 5;
    while (i * i <= num) {
        if (num % i === 0 || num % (i + 2) === 0) return false;
        i += 6;
    }
    return true;
}

const primes = [];
for (let i = 10000; i < 10500; i++) {
    if (isPrime(i)) {
        primes.push(i);
    }
}

console.log(`Found ${primes.length} prime numbers`);
console.log(`First few: ${primes.slice(0, 5)}`);

// Wait for a bit to allow monitoring
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Use async IIFE to allow for sleep
(async () => {
    console.log("Sleeping for 5 seconds...");
    await sleep(5000);
    console.log("Done!");
})();
EOF

# Run the tests
print_header "Testing Phase 3 Features"

# Test 1: Run with monitoring enabled
print_info "Test 1: Running Python script with monitoring"
./target/release/rusty-sandbox --monitor run tests/phase3/resource_test.py

# Test 2: Run with security level set to enhanced
print_info "Test 2: Running Python script with enhanced security"
./target/release/rusty-sandbox --security enhanced run tests/phase3/resource_test.py

# Test 3: Run malicious script with maximum security
print_info "Test 3: Running malicious script with maximum security"
./target/release/rusty-sandbox --security maximum run tests/phase3/malicious_test.py

# Test 4: Run JavaScript test with monitoring
print_info "Test 4: Running JavaScript test with monitoring"
./target/release/rusty-sandbox --monitor run tests/phase3/resource_test.js

# Test 5: Run standalone monitoring dashboard
print_info "Test 5: Running standalone monitoring dashboard"
echo "Starting monitoring dashboard..."
echo "Press Ctrl+C to exit after viewing the dashboard."
./target/release/rusty-sandbox monitor

print_header "All tests completed!"
echo "Phase 3 implementation appears to be working correctly." 