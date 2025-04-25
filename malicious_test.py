#!/usr/bin/env python3

"""
A Python script containing various potentially malicious operations.
This should be caught by the RustySandbox linter.
"""

import os
import sys
import subprocess

def malicious_operations():
    print("This script attempts various potentially malicious operations")
    
    # Try to access file system
    print("\n--- File System Access ---")
    try:
        # Read sensitive system file
        with open("/etc/passwd", "r") as f:
            data = f.read(100)  # Just read a bit to verify access
            print(f"SUCCESS: Read from /etc/passwd: {data[:50]}...")
    except Exception as e:
        print(f"BLOCKED: Could not read /etc/passwd: {e}")
    
    # Try to execute system commands
    print("\n--- Command Execution ---")
    try:
        output = os.system("ls -la /")
        print(f"SUCCESS: Executed system command with exit code: {output}")
    except Exception as e:
        print(f"BLOCKED: Could not execute system command: {e}")
    
    # Try subprocess
    try:
        output = subprocess.check_output(["ps", "aux"])
        print(f"SUCCESS: Executed subprocess, output length: {len(output)} bytes")
    except Exception as e:
        print(f"BLOCKED: Could not execute subprocess: {e}")
    
    # Try dynamic code execution
    print("\n--- Dynamic Code Execution ---")
    try:
        code = "print('This is dynamically executed code via exec()')"
        exec(code)
    except Exception as e:
        print(f"BLOCKED: Could not execute dynamic code: {e}")
    
    # Try dynamic evaluation
    try:
        result = eval("__import__('os').listdir('/')")
        print(f"SUCCESS: Evaluated code dynamically, result: {result[:5]}...")
    except Exception as e:
        print(f"BLOCKED: Could not evaluate code dynamically: {e}")
    
    print("\nMalicious operations test completed")
    return 0

if __name__ == "__main__":
    malicious_operations() 