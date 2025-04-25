mod python;
mod javascript;
mod wasm;

pub use python::PythonExecutor;
pub use javascript::JavaScriptExecutor;
pub use wasm::WasmExecutor;

use crate::runtime::{RuntimeRegistry, RuntimeExecutor};

/// Initialize runtime registry with all available executors
pub fn init_registry() -> RuntimeRegistry {
    let mut registry = RuntimeRegistry::new();
    
    // Register all available executors
    registry.register(Box::new(PythonExecutor::new()));
    registry.register(Box::new(JavaScriptExecutor::new()));
    registry.register(Box::new(WasmExecutor::new()));
    
    registry
} 