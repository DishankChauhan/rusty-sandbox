#!/usr/bin/env python3

"""
A CPU-intensive test for RustySandbox to measure real execution performance.
This will recursively calculate Fibonacci numbers which is computationally expensive.
"""

import time

def fibonacci_recursive(n):
    """Calculate Fibonacci recursively (inefficient by design to stress CPU)"""
    if n <= 1:
        return n
    return fibonacci_recursive(n-1) + fibonacci_recursive(n-2)

def main():
    start_time = time.time()
    
    # Calculate some medium-sized Fibonacci numbers
    results = []
    for i in range(30, 37):
        iter_start = time.time()
        result = fibonacci_recursive(i)
        iter_time = time.time() - iter_start
        results.append((i, result, iter_time))
        print(f"Fibonacci({i}) = {result} (took {iter_time:.4f} seconds)")
    
    total_time = time.time() - start_time
    print(f"\nTotal calculation time: {total_time:.4f} seconds")
    
    return 0

if __name__ == "__main__":
    main() 