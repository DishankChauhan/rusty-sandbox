#!/usr/bin/env python3

"""
An extremely resource-intensive test designed to trigger the sandbox limits.
This script is safe but deliberately inefficient and resource-hungry.
"""

import time

def extreme_memory_usage(size_mb):
    """Attempt to use an extreme amount of memory"""
    print(f"Attempting to allocate {size_mb}MB of memory...")
    
    # Convert to number of elements (each float is 8 bytes)
    elements = (size_mb * 1024 * 1024) // 8
    
    try:
        # Create a large array
        large_array = [0.0] * elements
        print(f"Successfully allocated array with {len(large_array):,} elements")
        
        # Use the array to make sure it's really allocated
        print("Manipulating array...")
        for i in range(0, len(large_array), len(large_array)//20):
            large_array[i] = i * 3.14159
        
        # Create a second array to use even more memory
        print("Allocating a second array...")
        another_array = [1.0] * elements
        print(f"Successfully allocated second array with {len(another_array):,} elements")
        
        # Keep both arrays in memory
        print(f"Total memory used: approximately {size_mb*2}MB")
        return (large_array, another_array)
    except MemoryError:
        print(f"Memory allocation failed at {size_mb}MB - hit memory limit!")
        return None

def extreme_cpu_usage(n):
    """Perform an extremely CPU-intensive calculation"""
    print(f"Starting extremely CPU-intensive calculation (n={n})...")
    
    start_time = time.time()
    
    # Very inefficient Fibonacci implementation
    def fibonacci(n):
        if n <= 1:
            return n
        return fibonacci(n-1) + fibonacci(n-2)
    
    try:
        result = fibonacci(n)
        elapsed = time.time() - start_time
        print(f"Fibonacci({n}) = {result}")
        print(f"Calculation took {elapsed:.2f} seconds")
    except Exception as e:
        print(f"Calculation failed: {e}")
        elapsed = time.time() - start_time
        print(f"Failed after {elapsed:.2f} seconds")

def main():
    print("=== EXTREME RESOURCE USAGE TEST ===")
    print("This test will attempt to push the sandbox to its limits")
    
    # First, try to use a lot of memory
    print("\n--- EXTREME MEMORY TEST ---")
    arrays = extreme_memory_usage(200)  # Try to allocate 200MB (then another 200MB)
    
    # Then, try to use a lot of CPU
    print("\n--- EXTREME CPU TEST ---")
    extreme_cpu_usage(39)  # Should take a very long time
    
    # Keep result in memory
    if arrays:
        print(f"\nMaintaining arrays with total size of approximately 400MB")
    
    print("\nTest completed!")
    return 0

if __name__ == "__main__":
    main() 