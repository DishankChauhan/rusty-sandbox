#!/usr/bin/env python3

"""
A Python script designed to be resource-intensive to test the sandbox limits.
This script is safe but deliberately inefficient.
"""

import time

def memory_intensive_operation(size_mb):
    """Allocate and use a large amount of memory"""
    print(f"Allocating approximately {size_mb}MB of memory...")
    
    # Each element is 8 bytes, so divide by 8 to get number of elements
    elements = (size_mb * 1024 * 1024) // 8
    large_array = [0.0] * elements
    
    # Use the array to ensure it's not optimized away
    print(f"Array created with {len(large_array):,} elements")
    print("Performing operations on array...")
    
    # Do some work with the array
    start = time.time()
    for i in range(0, len(large_array), 1000000):
        large_array[i] = i * 2
    
    sum_value = sum(large_array[::1000000])
    elapsed = time.time() - start
    
    print(f"Operations completed in {elapsed:.2f} seconds")
    print(f"Sample sum: {sum_value}")
    
    return large_array  # Return to prevent garbage collection

def cpu_intensive_operation(n):
    """Perform a CPU-intensive calculation"""
    print(f"Starting CPU-intensive calculation with n={n}...")
    
    start = time.time()
    
    # Inefficient Fibonacci calculation (deliberately)
    def fib(n):
        if n <= 1:
            return n
        return fib(n-1) + fib(n-2)
    
    result = fib(n)
    elapsed = time.time() - start
    
    print(f"Fibonacci({n}) = {result}")
    print(f"Calculation completed in {elapsed:.2f} seconds")

def main():
    print("Starting resource-intensive operations...")
    
    # First use a lot of memory
    array = memory_intensive_operation(175)  # Try to allocate 175MB
    
    # Then do CPU-intensive work
    cpu_intensive_operation(37)  # Computationally expensive
    
    # Keep the array in memory
    print(f"Maintaining array of {len(array):,} elements in memory")
    
    print("All operations completed successfully")
    return 0

if __name__ == "__main__":
    main() 