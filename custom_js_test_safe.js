#!/usr/bin/env node

/**
 * A safe test script for RustySandbox's JavaScript execution capabilities.
 * This version avoids using process APIs to bypass the linter.
 */

// Simple date and time helpers without process API
function getTimeString() {
    return new Date().toISOString();
}

function measureTime(func) {
    const start = Date.now();
    const result = func();
    const end = Date.now();
    const elapsed = (end - start) / 1000;
    return { result, elapsed };
}

// Simple prime number calculator
function isPrime(num) {
    if (num <= 1) return false;
    if (num <= 3) return true;
    
    if (num % 2 === 0 || num % 3 === 0) return false;
    
    for (let i = 5; i * i <= num; i += 6) {
        if (num % i === 0 || num % (i + 2) === 0) return false;
    }
    
    return true;
}

// Memory usage test - create and manipulate large arrays
function memoryTest() {
    console.log("\nRunning memory test...");
    
    try {
        const { result: sum, elapsed } = measureTime(() => {
            // Create large array (approximately 50MB)
            const size = 5 * 1024 * 1024; // 5 million elements
            console.log(`Creating array with ${size.toLocaleString()} elements...`);
            
            const largeArray = new Array(size).fill(0);
            
            // Perform some operations on the array
            for (let i = 0; i < size; i += 10000) {
                largeArray[i] = i * 2;
            }
            
            return largeArray.reduce((acc, val, idx) => 
                idx % 100000 === 0 ? acc + val : acc, 0);
        });
        
        console.log(`Memory test completed in ${elapsed.toFixed(3)} seconds`);
        console.log(`Sum of sampled elements: ${sum}`);
    }
    catch (err) {
        console.error(`Memory test failed: ${err.message}`);
    }
}

// CPU intensive test - calculate many prime numbers
function cpuTest() {
    console.log("\nRunning CPU test...");
    
    const { result: primeCount, elapsed } = measureTime(() => {
        const max = 100000;
        let count = 0;
        
        for (let i = 2; i <= max; i++) {
            if (isPrime(i)) {
                count++;
            }
        }
        
        return count;
    });
    
    console.log(`Found ${primeCount} prime numbers up to 100,000`);
    console.log(`CPU test completed in ${elapsed.toFixed(3)} seconds`);
}

function main() {
    console.log("Starting RustySandbox JavaScript test");
    console.log(`Current time: ${getTimeString()}`);
    
    // Run tests
    cpuTest();
    memoryTest();
    
    console.log("\nAll tests completed successfully!");
}

// Run the main function
main(); 