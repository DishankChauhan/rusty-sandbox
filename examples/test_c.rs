use std::process::{Command, Stdio};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::fs;

fn main() {
    // Create a temporary C file if it doesn't exist
    let hello_c_path = Path::new("examples/hello.c");
    
    if !hello_c_path.exists() {
        println!("Creating example C file...");
        let code = r#"#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("Hello from C in the rusty-sandbox!\n");
    
    // Test memory allocation
    int *array = malloc(10 * sizeof(int));
    if (array) {
        for (int i = 0; i < 10; i++) {
            array[i] = i * i;
        }
        
        printf("Squares: ");
        for (int i = 0; i < 10; i++) {
            printf("%d ", array[i]);
        }
        printf("\n");
        
        free(array);
    }
    
    return 0;
}"#;
        
        fs::write(hello_c_path, code).expect("Failed to write C file");
    }
    
    // Find GCC or alternative C compiler
    let compiler = find_c_compiler();
    println!("Using C compiler: {:?}", compiler);
    
    // Compile the C program
    let output_path = PathBuf::from("examples/hello");
    let compile_status = Command::new(&compiler)
        .args(["-Wall", "-o"])
        .arg(&output_path)
        .arg(hello_c_path)
        .status()
        .expect("Failed to execute compiler");
        
    if !compile_status.success() {
        panic!("Compilation failed with status: {}", compile_status);
    }
    
    println!("Compilation successful!");
    
    // Run the compiled program
    let output = Command::new(&output_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute program");
        
    println!("\nProgram output:");
    println!("==============");
    println!("{}", String::from_utf8_lossy(&output.stdout));
    
    if !output.stderr.is_empty() {
        println!("Error output:");
        println!("{}", String::from_utf8_lossy(&output.stderr));
    }
    
    println!("Exit status: {}", output.status);
}

fn find_c_compiler() -> PathBuf {
    // Try common C compiler names
    for compiler in &["gcc", "clang", "cc"] {
        if let Ok(output) = Command::new("which").arg(compiler).output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                return PathBuf::from(path);
            }
        }
    }
    
    panic!("No C compiler found in PATH");
} 