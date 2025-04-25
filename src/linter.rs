use anyhow::{Result, anyhow};
use regex::Regex;
use std::collections::HashMap;
use tracing::warn;

use crate::sandbox::FileType;

pub fn check_for_dangerous_code(content: &str, file_type: FileType) -> Result<()> {
    match file_type {
        FileType::Python => check_python_code(content),
        FileType::JavaScript => check_javascript_code(content),
    }
}

fn check_python_code(content: &str) -> Result<()> {
    let dangerous_patterns = [
        // System execution
        (r"os\.system", "Direct system command execution"),
        (r"subprocess", "Subprocess execution"),
        (r"exec\(", "Dynamic code execution via exec()"),
        (r"eval\(", "Dynamic code evaluation via eval()"),
        
        // File operations outside of safe paths
        (r"open\(", "Potentially unsafe file operations"),
        (r"__import__", "Dynamic module importing"),
        
        // Network operations
        (r"urllib|requests|http|socket", "Network operations"),
        
        // Dangerous libraries
        (r"import os", "OS module import"),
        (r"from os import", "OS module import"),
        (r"import sys", "SYS module import"),
        (r"from sys import", "SYS module import"),
        (r"import subprocess", "Subprocess module import"),
        (r"from subprocess import", "Subprocess module import"),
        (r"import shutil", "Shutil module import"),
        (r"from shutil import", "Shutil module import"),
        
        // Other dangerous operations
        (r"globals\(", "Globals manipulation"),
        (r"locals\(", "Locals manipulation"),
        (r"getattr\(", "Dynamic attribute access"),
        (r"setattr\(", "Dynamic attribute setting"),
    ];
    
    check_patterns(content, &dangerous_patterns)
}

fn check_javascript_code(content: &str) -> Result<()> {
    // Only match patterns that are actually dangerous
    // Make sure not to match harmless code
    let dangerous_patterns = [
        // System execution
        (r"child_process", "Node.js child process module"),
        (r"\.exec\(", "Process execution"),
        (r"\.spawn\(", "Process execution"),
        (r"eval\(", "Dynamic code evaluation via eval()"),
        (r"new Function", "Dynamic code via Function constructor"),
        
        // File operations - only match explicit file system operations
        (r"require.*fs", "File system operations"),
        (r"fs\.", "File system operations"),
        (r"readFile", "File read operations"),
        (r"writeFile", "File write operations"),
        (r"appendFile", "File append operations"),
        
        // Network operations - only match explicit network operations
        (r"require.*http", "HTTP module"),
        (r"require.*https", "HTTPS module"),
        (r"require.*net", "Network module"),
        (r"require.*dgram", "UDP module"),
        
        // Dangerous process operations
        (r"process\.exit", "Process exit"),
        (r"process\.kill", "Process kill"),
        (r"process\.env", "Process environment access"),
        
        // Other dangerous operations
        (r"require.*crypto", "Cryptography operations"),
    ];
    
    check_patterns(content, &dangerous_patterns)
}

fn check_patterns(content: &str, patterns: &[(& str, &str)]) -> Result<()> {
    let mut found_patterns = HashMap::new();
    
    for (pattern, description) in patterns {
        match Regex::new(pattern) {
            Ok(regex) => {
                if regex.is_match(content) {
                    found_patterns.insert(pattern, description);
                }
            }
            Err(e) => {
                warn!("Invalid regex pattern {}: {}", pattern, e);
            }
        }
    }
    
    if found_patterns.is_empty() {
        Ok(())
    } else {
        let mut error_message = String::from("Potentially dangerous code patterns found:\n");
        
        for (pattern, description) in found_patterns {
            error_message.push_str(&format!("- {} ({})\n", description, pattern));
        }
        
        Err(anyhow!(error_message))
    }
} 