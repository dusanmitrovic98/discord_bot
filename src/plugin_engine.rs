//! # Dynamic WebAssembly Plugin Engine
//!
//! Sandboxed microkernel executing community WASM plugins via Wasmtime.
//! Features fuel bounding (NASA Rule 2), module pre-compilation, host entropy,
//! and asynchronous gateway event dispatching across all 30+ Discord hooks.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::info;
use wasmtime::*;

use crate::db::DatabaseEngine;
use crate::{AegisError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashCommandDef {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub slash_commands: Vec<SlashCommandDef>,
    pub http_routes: Vec<String>,
    pub cron_interval_secs: Option<u64>,
    pub capabilities: Vec<String>,
    pub subscribed_events: Vec<String>,
}

impl Default for PluginManifest {
    fn default() -> Self {
        Self {
            name: "unnamed_plugin".into(),
            version: "0.1.0".into(),
            author: "Unknown".into(),
            description: "No description".into(),
            slash_commands: Vec::new(),
            http_routes: Vec::new(),
            cron_interval_secs: None,
            capabilities: Vec::new(),
            subscribed_events: Vec::new(),
        }
    }
}

pub struct LoadedPlugin {
    pub manifest: PluginManifest,
    pub module: Module,
    pub wasm_bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct DynamicPluginEngine {
    engine: Engine,
    registry: Arc<RwLock<HashMap<String, LoadedPlugin>>>,
    db: Option<Arc<DatabaseEngine>>,
}

impl Default for DynamicPluginEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamicPluginEngine {
    pub fn new() -> Self {
        let mut config = Config::new();
        config.consume_fuel(true); // NASA Rule 2: Strict execution bounding
        let engine = Engine::new(&config).expect("Wasmtime engine initialization failed");

        Self {
            engine,
            registry: Arc::new(RwLock::new(HashMap::new())),
            db: None,
        }
    }

    pub fn with_db(mut self, db: Arc<DatabaseEngine>) -> Self {
        self.db = Some(db);
        self
    }

    /// Pre-populates host functions (entropy, capabilities) exposed to guest sandboxes
    fn build_linker(&self) -> Result<Linker<()>> {
        let mut linker = Linker::new(&self.engine);
        linker
            .func_wrap("env", "host_random_u32", || -> u32 {
                rand::random::<u32>()
            })
            .map_err(|e| {
                AegisError::PluginError(format!("Failed to register host imports: {}", e))
            })?;
        Ok(linker)
    }

    /// Loads or hot-swaps a WASM plugin bytecode module in memory atomically
    pub fn hot_swap_plugin(&self, name: &str, wasm_bytes: &[u8]) -> Result<PluginManifest> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| AegisError::PluginError(format!("WASM compilation failed: {}", e)))?;

        let manifest = self.extract_manifest(&module)?;

        let mut write_guard = self
            .registry
            .write()
            .map_err(|_| AegisError::PluginError("Registry lock poisoned".into()))?;

        write_guard.insert(
            name.to_string(),
            LoadedPlugin {
                manifest: manifest.clone(),
                module,
                wasm_bytes: wasm_bytes.to_vec(),
            },
        );

        info!(
            "WASM Plugin '{}' (v{}) loaded in memory. Slash commands: {}",
            manifest.name,
            manifest.version,
            manifest.slash_commands.len()
        );
        Ok(manifest)
    }

    pub fn unload_plugin(&self, name: &str) {
        if let Ok(mut write_guard) = self.registry.write() {
            write_guard.remove(name);
            info!("WASM Plugin '{}' unloaded from memory.", name);
        }
    }

    pub fn get_manifest(&self, name: &str) -> Option<PluginManifest> {
        let read_guard = self.registry.read().ok()?;
        read_guard.get(name).map(|p| p.manifest.clone())
    }

    pub fn get_all_manifests(&self) -> Vec<PluginManifest> {
        if let Ok(read_guard) = self.registry.read() {
            read_guard.values().map(|p| p.manifest.clone()).collect()
        } else {
            Vec::new()
        }
    }

    /// Fast-path check: returns true if any active plugin listens to this event (NASA Rule 2)
    pub fn has_subscribers_for(&self, event_name: &str) -> bool {
        let guard = match self.registry.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        guard.values().any(|p| {
            p.manifest
                .subscribed_events
                .iter()
                .any(|e| e == event_name || e == "*")
        })
    }

    /// Asynchronously broadcasts an event payload to all subscribed plugins in detached Tokio tasks
    pub fn dispatch_event(&self, event_name: &str, payload_json: &str) {
        let plugins: Vec<(String, Module, Vec<String>)> = match self.registry.read() {
            Ok(guard) => guard
                .iter()
                .map(|(name, p)| {
                    (
                        name.clone(),
                        p.module.clone(),
                        p.manifest.subscribed_events.clone(),
                    )
                })
                .collect(),
            Err(_) => return,
        };

        for (name, module, subscriptions) in plugins {
            if !subscriptions.iter().any(|e| e == event_name || e == "*") {
                continue;
            }

            let engine_clone = self.clone();
            let event_name = event_name.to_string();
            let payload = payload_json.to_string();

            tokio::spawn(async move {
                let timeout_res = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    engine_clone.execute_event_sync(&name, &module, &event_name, &payload),
                )
                .await;

                if let Err(_) = timeout_res {
                    tracing::warn!(
                        "⚠️ [EVENT TIMEOUT] Plugin '{}' timed out on '{}'",
                        name,
                        event_name
                    );
                }
            });
        }
    }

    async fn execute_event_sync(
        &self,
        _plugin_name: &str,
        module: &Module,
        event_name: &str,
        payload_json: &str,
    ) -> Result<()> {
        let mut store = Store::new(&self.engine, ());
        store
            .set_fuel(100_000)
            .map_err(|e| AegisError::PluginError(e.to_string()))?;

        let linker = self.build_linker()?;
        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| AegisError::PluginError(e.to_string()))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| AegisError::PluginError("Plugin lacks exported linear memory".into()))?;

        let input_json = serde_json::json!({
            "event": event_name,
            "data": payload_json
        })
        .to_string();

        let input_bytes = input_json.as_bytes();
        let alloc_fn = match instance.get_typed_func::<i32, i32>(&mut store, "alloc") {
            Ok(f) => f,
            Err(_) => return Ok(()),
        };

        let ptr = alloc_fn
            .call(&mut store, input_bytes.len() as i32)
            .map_err(|e| AegisError::PluginError(format!("Alloc trapped: {}", e)))?
            as usize;

        memory.data_mut(&mut store)[ptr..ptr + input_bytes.len()].copy_from_slice(input_bytes);

        if let Ok(on_event_fn) = instance.get_typed_func::<(i32, i32), i32>(&mut store, "on_event")
        {
            let _ = on_event_fn.call(&mut store, (ptr as i32, input_bytes.len() as i32));
        }

        Ok(())
    }

    fn extract_manifest(&self, module: &Module) -> Result<PluginManifest> {
        let mut store = Store::new(&self.engine, ());
        store
            .set_fuel(500_000)
            .map_err(|e| AegisError::PluginError(e.to_string()))?;

        let linker = self.build_linker()?;
        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| AegisError::PluginError(format!("Instantiation failed: {}", e)))?;

        if let Ok(manifest_fn) = instance.get_typed_func::<(), i64>(&mut store, "get_manifest") {
            let packed = manifest_fn
                .call(&mut store, ())
                .map_err(|e| AegisError::PluginError(format!("Manifest call trapped: {}", e)))?;

            let memory = instance.get_memory(&mut store, "memory").ok_or_else(|| {
                AegisError::PluginError("Plugin lacks exported linear memory".into())
            })?;

            let ptr = (packed >> 32) as usize;
            let len = (packed & 0xFFFF_FFFF) as usize;

            let mem_slice = memory.data(&store);
            if ptr + len <= mem_slice.len() {
                let json_str = std::str::from_utf8(&mem_slice[ptr..ptr + len])
                    .map_err(|e| {
                        AegisError::PluginError(format!("Invalid UTF-8 in manifest: {}", e))
                    })?
                    .trim_end_matches('\0');
                let manifest: PluginManifest = serde_json::from_str(json_str).map_err(|e| {
                    AegisError::PluginError(format!("Invalid manifest JSON: {}", e))
                })?;
                return Ok(manifest);
            }
        }

        Ok(PluginManifest::default())
    }

    pub fn execute_slash_command(
        &self,
        plugin_name: &str,
        command_name: &str,
        options_json: &str,
    ) -> Result<String> {
        let read_guard = self
            .registry
            .read()
            .map_err(|_| AegisError::PluginError("Registry lock poisoned".into()))?;

        let plugin = read_guard.get(plugin_name).ok_or_else(|| {
            AegisError::PluginError(format!("Plugin '{}' not loaded", plugin_name))
        })?;

        let mut store = Store::new(&self.engine, ());
        store
            .set_fuel(1_000_000)
            .map_err(|e| AegisError::PluginError(e.to_string()))?;

        let linker = self.build_linker()?;
        let instance = linker
            .instantiate(&mut store, &plugin.module)
            .map_err(|e| AegisError::PluginError(e.to_string()))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| AegisError::PluginError("Plugin lacks exported linear memory".into()))?;

        let input_payload = serde_json::json!({
            "command": command_name,
            "options": options_json
        })
        .to_string();

        let input_bytes = input_payload.as_bytes();
        let alloc_fn = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|_| AegisError::PluginError("Plugin missing 'alloc' export".into()))?;

        let input_ptr = alloc_fn
            .call(&mut store, input_bytes.len() as i32)
            .map_err(|e| AegisError::PluginError(format!("Alloc trapped: {}", e)))?
            as usize;

        memory.data_mut(&mut store)[input_ptr..input_ptr + input_bytes.len()]
            .copy_from_slice(input_bytes);

        let handler_fn = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "on_slash_command")
            .map_err(|_| {
                AegisError::PluginError("Plugin missing 'on_slash_command' export".into())
            })?;

        let packed = handler_fn
            .call(&mut store, (input_ptr as i32, input_bytes.len() as i32))
            .map_err(|e| AegisError::PluginError(format!("Plugin execution trapped: {}", e)))?;

        let out_ptr = (packed >> 32) as usize;
        let out_len = (packed & 0xFFFF_FFFF) as usize;

        let mem_slice = memory.data(&store);
        if out_ptr + out_len <= mem_slice.len() {
            let output_str =
                std::str::from_utf8(&mem_slice[out_ptr..out_ptr + out_len]).map_err(|e| {
                    AegisError::PluginError(format!("Invalid UTF-8 in response: {}", e))
                })?;
            Ok(output_str.to_string())
        } else {
            Err(AegisError::PluginError(
                "Plugin returned out-of-bounds pointer".into(),
            ))
        }
    }

    pub fn execute_http_request(
        &self,
        plugin_name: &str,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<(u16, String)> {
        let read_guard = self
            .registry
            .read()
            .map_err(|_| AegisError::PluginError("Registry lock poisoned".into()))?;

        let plugin = read_guard.get(plugin_name).ok_or_else(|| {
            AegisError::PluginError(format!("Plugin '{}' not loaded", plugin_name))
        })?;

        let mut store = Store::new(&self.engine, ());
        store
            .set_fuel(1_000_000)
            .map_err(|e| AegisError::PluginError(e.to_string()))?;

        let linker = self.build_linker()?;
        let instance = linker
            .instantiate(&mut store, &plugin.module)
            .map_err(|e| AegisError::PluginError(e.to_string()))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| AegisError::PluginError("Plugin lacks exported memory".into()))?;

        let req_json = serde_json::json!({
            "method": method,
            "path": path,
            "body": String::from_utf8_lossy(body)
        })
        .to_string();

        let req_bytes = req_json.as_bytes();
        let alloc_fn = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|_| AegisError::PluginError("Missing 'alloc'".into()))?;

        let ptr = alloc_fn
            .call(&mut store, req_bytes.len() as i32)
            .map_err(|e| AegisError::PluginError(format!("Alloc trapped: {}", e)))?
            as usize;

        memory.data_mut(&mut store)[ptr..ptr + req_bytes.len()].copy_from_slice(req_bytes);

        if let Ok(http_fn) =
            instance.get_typed_func::<(i32, i32), i64>(&mut store, "on_http_request")
        {
            let packed = http_fn
                .call(&mut store, (ptr as i32, req_bytes.len() as i32))
                .map_err(|e| AegisError::PluginError(format!("HTTP trapped: {}", e)))?;

            let out_ptr = (packed >> 32) as usize;
            let out_len = (packed & 0xFFFF_FFFF) as usize;
            let mem = memory.data(&store);

            if out_ptr + out_len <= mem.len() {
                let resp_str =
                    std::str::from_utf8(&mem[out_ptr..out_ptr + out_len]).unwrap_or("{}");
                return Ok((200, resp_str.to_string()));
            }
        }

        Ok((404, "Plugin did not handle route".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandboxed_wasm_execution_with_host_entropy() {
        let engine = DynamicPluginEngine::new();

        let wat = r#"
            (module
                (import "env" "host_random_u32" (func $host_random_u32 (result i32)))
                (memory (export "memory") 1)
                
                (data (i32.const 0) "{\"name\":\"test_flip\",\"slash_commands\":[{\"name\":\"flip\",\"description\":\"Flip\"}]}")
                (data (i32.const 100) "HEADS")
                (data (i32.const 200) "TAILS")
                
                (func (export "alloc") (param i32) (result i32)
                    i32.const 500
                )
                (func (export "get_manifest") (result i64)
                    i64.const 78
                )
                (func (export "on_slash_command") (param i32 i32) (result i64)
                    (if (result i64) (i32.eq (i32.and (call $host_random_u32) (i32.const 1)) (i32.const 0))
                        (then i64.const 429496729605)  ;; (100 << 32) | 5 -> HEADS
                        (else i64.const 858993459205)  ;; (200 << 32) | 5 -> TAILS
                    )
                )
            )
        "#;

        let wasm_bytes = wat::parse_str(wat).expect("WAT parse failed");
        let manifest = engine
            .hot_swap_plugin("test_flip", &wasm_bytes)
            .expect("Hot swap failed");
        assert_eq!(manifest.name, "test_flip");

        let mut seen_heads = false;
        let mut seen_tails = false;

        for _ in 0..50 {
            let res = engine
                .execute_slash_command("test_flip", "flip", "{}")
                .unwrap();
            if res == "HEADS" {
                seen_heads = true;
            }
            if res == "TAILS" {
                seen_tails = true;
            }
        }

        assert!(
            seen_heads && seen_tails,
            "Host entropy must produce both HEADS and TAILS outcomes"
        );
    }

    #[tokio::test]
    async fn test_wasm_gateway_event_dispatch() {
        let engine = DynamicPluginEngine::new();

        let wat = r#"
            (module
                (memory (export "memory") 1)
                
                (data (i32.const 0) "{\"name\":\"event_listener\",\"subscribed_events\":[\"message_create\"]}")
                
                (func (export "alloc") (param i32) (result i32)
                    i32.const 500
                )
                (func (export "get_manifest") (result i64)
                    i64.const 73
                )
                (func (export "on_event") (param i32 i32) (result i32)
                    i32.const 0
                )
            )
        "#;

        let wasm_bytes = wat::parse_str(wat).expect("WAT parse failed");
        let manifest = engine
            .hot_swap_plugin("event_listener", &wasm_bytes)
            .expect("Hot swap failed");

        assert_eq!(manifest.name, "event_listener");
        assert_eq!(
            manifest.subscribed_events,
            vec!["message_create".to_string()]
        );

        assert!(engine.has_subscribers_for("message_create"));
        assert!(!engine.has_subscribers_for("voice_state_update"));

        engine.dispatch_event("message_create", "{\"content\":\"test\"}");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
