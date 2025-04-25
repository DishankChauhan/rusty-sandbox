#!/usr/bin/env node

/**
 * A simple JavaScript example to test the RustySandbox.
 * This script doesn't contain any dangerous operations.
 */

function main() {
    console.log("Hello from the RustySandbox!");
    console.log("This is a safe JavaScript script.");
    
    // Calculate Fibonacci sequence
    const fibonacci = [0, 1];
    for (let i = 2; i < 10; i++) {
        fibonacci.push(fibonacci[i-1] + fibonacci[i-2]);
    }
    
    console.log(`Fibonacci sequence: ${fibonacci.join(', ')}`);
    
    // Demonstrate a loop
    let total = 0;
    for (let i = 1; i <= 5; i++) {
        total += i;
        console.log(`Adding ${i}: total is now ${total}`);
    }
    
    // Demonstrate some array operations
    const numbers = [1, 2, 3, 4, 5];
    const squared = numbers.map(n => n * n);
    console.log(`Squared numbers: ${squared.join(', ')}`);
    
    return 0;
}

// Run the main function without using process.exit
main(); 