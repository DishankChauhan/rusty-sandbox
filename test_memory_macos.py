#!/usr/bin/env python3

"""
Memory escalation test for RustySandbox on macOS.
This script progressively allocates more memory to test the memory monitoring system.
"""

import time
import array

def format_mb(bytes_value):
    """Format bytes as MB"""
    return f"{bytes_value / (1024 * 1024):.2f} MB"

def main():
    print("Starting macOS memory monitoring test")
    print("This script will gradually allocate memory until terminated")
    
    # Start with a small array (1 MB chunks)
    chunk_size_mb = 10
    chunk_size = chunk_size_mb * 1024 * 1024
    
    # Store each allocation in a list to prevent garbage collection
    allocations = []
    total_allocated = 0
    
    try:
        for i in range(1, 30):  # Try to allocate up to 300 MB (in 10 MB chunks)
            print(f"\nAttempt #{i}: Allocating {chunk_size_mb} MB chunk...")
            start_time = time.time()
            
            # Create a chunk of memory (float array = 8 bytes per element)
            chunk = array.array('d', [1.0] * (chunk_size // 8))
            allocations.append(chunk)
            
            # Update the total
            total_allocated += chunk_size
            
            # Report statistics
            elapsed = time.time() - start_time
            print(f"Successfully allocated {format_mb(chunk_size)} in {elapsed:.3f} seconds")
            print(f"Total memory allocated so far: {format_mb(total_allocated)}")
            
            # Sleep to give the memory monitor time to check
            print(f"Sleeping for 0.5 seconds...")
            time.sleep(0.5)
    
    except MemoryError:
        print(f"Memory allocation failed at {format_mb(total_allocated)}")
    
    except Exception as e:
        print(f"Unexpected error: {e}")
    
    # Keep memory allocated to maintain pressure
    print("\nHolding allocated memory for 5 seconds...")
    time.sleep(5)
    
    print("\nTest completed")
    return 0

if __name__ == "__main__":
    main() 