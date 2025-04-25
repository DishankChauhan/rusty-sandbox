#!/usr/bin/env python3

"""
A demonstration script with potentially dangerous code patterns.
This should be caught by the RustySandbox linter.
"""

import os
import sys
import subprocess

def dangerous_operations():
    print("This script contains dangerous operations")
    
    # System command execution (dangerous)
    os.system("ls -la")
    
    # Subprocess execution (dangerous)
    subprocess.run(["echo", "Hello from subprocess"], check=True)
    
    # File operations (potentially dangerous)
    with open("/etc/passwd", "r") as f:
        data = f.read()
        print(f"Read {len(data)} bytes from /etc/passwd")
    
    # Dynamic code execution (dangerous)
    code = "print('Dynamic code execution')"
    exec(code)
    
    # Dynamic code evaluation (dangerous)
    result = eval("2 + 2")
    print(f"Result of eval: {result}")
    
    return 0

if __name__ == "__main__":
    dangerous_operations() 