#!/usr/bin/env python3

"""
A memory-intensive test for RustySandbox that avoids using system imports.
This will allocate progressively larger arrays to test memory limits.
"""

import time

def format_bytes(size_bytes):
    """Format a byte size into a readable string"""
    if size_bytes < 1024:
        return f"{size_bytes:.2f} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes/(1024*1024):.2f} MB"
    else:
        return f"{size_bytes/(1024*1024*1024):.2f} GB"

def main():
    print("Memory allocation test (safe version)")
    
    # Test memory allocation in increasing steps
    sizes = [10, 25, 50, 100, 150, 200]
    for size_mb in sizes:
        size_bytes = size_mb * 1024 * 1024
        # Convert to number of elements (assuming 8 bytes per float)
        array_size = size_bytes // 8
        
        try:
            print(f"\nAttempting to allocate approximately {size_mb} MB...")
            start_time = time.time()
            
            # Allocate the memory (floating point numbers use more memory)
            large_array = [0.0] * array_size
            
            # Do something with the array to ensure it's actually allocated
            for i in range(0, len(large_array), len(large_array)//10):
                large_array[i] = i
                
            allocation_time = time.time() - start_time
            
            print(f"Successfully allocated array of {len(large_array):,} elements")
            print(f"Approximate size: {format_bytes(len(large_array) * 8)}")
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