use crate::{AegisError, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::info;
use wasmtime::*;

pub struct PluginContext {
    pub user_id: u64,
    pub content: String,
    pub is_actionable: bool,
}

pub struct ActivePlugin {
    pub name: String,
    pub instance: Instance,
    pub store: Store<()>,
}

#[derive(Clone)]
pub struct DynamicPluginEngine {
    engine: Engine,
    registry: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl Default for DynamicPluginEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamicPluginEngine {
    pub fn new() -> Self {
        let mut config = Config::new();
        config.consume_fuel(true); // NASA principle: bound WASM execution steps
        let engine = Engine::new(&config).expect("Wasmtime engine initialization failed");

        Self {
            engine,
            registry: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Loads or hot-swaps a WASM plugin bytecode module in memory atomically.
    pub fn hot_swap_plugin(&self, name: &str, wasm_bytes: &[u8]) -> Result<()> {
        // Validate compilation before accepting into memory
        let _module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| AegisError::PluginError(format!("WASM validation failed: {}", e)))?;

        let mut write_guard = self
            .registry
            .write()
            .map_err(|_| AegisError::PluginError("Registry lock poisoned".into()))?;

        write_guard.insert(name.to_string(), wasm_bytes.to_vec());
        info!(
            "WASM Plugin '{}' hot-swapped into memory successfully (Bytes: {}).",
            name,
            wasm_bytes.len()
        );
        Ok(())
    }

    /// Runs all active plugins against incoming message/user context.
    pub fn evaluate_all(&self, context: &mut PluginContext) -> Result<()> {
        let read_guard = self
            .registry
            .read()
            .map_err(|_| AegisError::PluginError("Registry lock poisoned".into()))?;

        for (name, wasm_bytes) in read_guard.iter() {
            let mut store = Store::new(&self.engine, ());
            store
                .set_fuel(500_000)
                .map_err(|e| AegisError::PluginError(e.to_string()))?; // Bound CPU cycles

            let module = Module::new(&self.engine, wasm_bytes)
                .map_err(|e| AegisError::PluginError(e.to_string()))?;

            let linker = Linker::new(&self.engine);
            let instance = linker
                .instantiate(&mut store, &module)
                .map_err(|e| AegisError::PluginError(e.to_string()))?;

            // Typed Host ABI: fn evaluate(len: i32) -> i32 (1 = flag, 0 = pass)
            if let Ok(eval_fn) = instance.get_typed_func::<i32, i32>(&mut store, "evaluate") {
                let verdict = eval_fn
                    .call(&mut store, context.content.len() as i32)
                    .unwrap_or(0);

                if verdict == 1 {
                    info!("Plugin '{}' intercepted and flagged context!", name);
                    context.is_actionable = true;
                    return Ok(());
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_hot_swapping_and_execution() {
        let engine = DynamicPluginEngine::new();

        // Minimal valid WASM module exporting `evaluate(len: i32) -> i32`
        // Returns 1 if input len > 10, else 0
        let wat = r#"
            (module
                (func (export "evaluate") (param i32) (result i32)
                    local.get 0
                    i32.const 10
                    i32.gt_s
                )
            )
        "#;
        let wasm_bytes = wat::parse_str(wat).expect("WAT parse failed");

        assert!(engine.hot_swap_plugin("length_filter", &wasm_bytes).is_ok());

        let mut ctx_short = PluginContext {
            user_id: 1,
            content: "safe".into(),
            is_actionable: false,
        };
        engine.evaluate_all(&mut ctx_short).unwrap();
        assert!(!ctx_short.is_actionable);

        let mut ctx_long = PluginContext {
            user_id: 2,
            content: "this_is_a_very_long_suspicious_payload".into(),
            is_actionable: false,
        };
        engine.evaluate_all(&mut ctx_long).unwrap();
        assert!(ctx_long.is_actionable);
    }
}
