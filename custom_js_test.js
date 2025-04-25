#!/usr/bin/env node

/**
 * A test script for RustySandbox's JavaScript execution capabilities.
 * This will perform various computations to test performance.
 */

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
        const startTime = process.hrtime();
        
        // Create large array (approximately 50MB)
        const size = 5 * 1024 * 1024; // 5 million elements
        console.log(`Creating array with ${size.toLocaleString()} elements...`);
        
        const largeArray = new Array(size).fill(0);
        
        // Perform some operations on the array
        for (let i = 0; i < size; i += 10000) {
            largeArray[i] = i * 2;
        }
        
        const sum = largeArray.reduce((acc, val, idx) => 
            idx % 100000 === 0 ? acc + val : acc, 0);
        
        const endTime = process.hrtime(startTime);
        const totalTime = (endTime[0] + endTime[1]/1e9).toFixed(3);
        
        console.log(`Memory test completed in ${totalTime} seconds`);
        console.log(`Sum of sampled elements: ${sum}`);
    }
    catch (err) {
        console.error(`Memory test failed: ${err.message}`);
    }
}

// CPU intensive test - calculate many prime numbers
function cpuTest() {
    console.log("\nRunning CPU test...");
    
    const startTime = process.hrtime();
    const max = 100000;
    
    let primeCount = 0;
    for (let i = 2; i <= max; i++) {
        if (isPrime(i)) {
            primeCount++;
        }
    }
    
    const endTime = process.hrtime(startTime);
    const totalTime = (endTime[0] + endTime[1]/1e9).toFixed(3);
    
    console.log(`Found ${primeCount} prime numbers up to ${max}`);
    console.log(`CPU test completed in ${totalTime} seconds`);
}

function main() {
    console.log("Starting RustySandbox JavaScript test");
    console.log(`Node.js version: ${process.version}`);
    
    // Run tests
    cpuTest();
    memoryTest();
    
    console.log("\nAll tests completed successfully!");
}

// Run the main function (without process.exit to avoid linter errors)
main(); 