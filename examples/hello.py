#!/usr/bin/env python3

"""
A simple example script to test the RustySandbox.
This script doesn't contain any dangerous operations.
"""

def main():
    print("Hello from the RustySandbox!")
    print("This is a safe Python script.")
    
    # Calculate Fibonacci sequence
    fibonacci = [0, 1]
    for i in range(2, 10):
        fibonacci.append(fibonacci[i-1] + fibonacci[i-2])
    
    print(f"Fibonacci sequence: {fibonacci}")
    
    # Demonstrate a loop
    total = 0
    for i in range(1, 6):
        total += i
        print(f"Adding {i}: total is now {total}")
    
    return 0

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code) 