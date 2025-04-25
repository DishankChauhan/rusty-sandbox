#!/usr/bin/env python3

"""
A memory-intensive test for RustySandbox to measure real memory usage.
This will allocate progressively larger arrays to test memory limits.
"""

import time
import sys

def format_size(size_bytes):
    """Format a byte size into a readable string"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024 or unit == 'GB':
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024

def main():
    print(f"Python version: {sys.version}")
    
    # Test memory allocation in increasing steps
    sizes = [10, 20, 50, 100, 200]
    for size_mb in sizes:
        size_bytes = size_mb * 1024 * 1024
        array_size = size_bytes // 8  # 8 bytes per float
        
        try:
            print(f"\nAttempting to allocate approximately {size_mb} MB...")
            start_time = time.time()
            
            # Allocate the memory as a list of floats
            large_array = [0.0] * array_size
            
            # Do something with the array to ensure it's actually allocated
            for i in range(0, len(large_array), len(large_array)//10):
                large_array[i] = i
                
            allocation_time = time.time() - start_time
            actual_size = sys.getsizeof(large_array)
            
            print(f"Successfully allocated array of {len(large_array)} elements")
            print(f"Reported size: {format_size(actual_size)}")
            print(f"Allocation time: {allocation_time:.4f} seconds")
            
            # Clear the array to free memory before next iteration
            del large_array
            
        except MemoryError:
            print(f"Memory allocation of {size_mb} MB failed - hit memory limit!")
            break
    
    print("\nMemory test completed")
    return 0

if __name__ == "__main__":
    main() 