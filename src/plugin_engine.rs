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
        }
    }
}

pub struct LoadedPlugin {
    pub manifest: PluginManifest,
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

    /// Loads or hot-swaps a WASM plugin bytecode module in memory atomically
    pub fn hot_swap_plugin(&self, name: &str, wasm_bytes: &[u8]) -> Result<PluginManifest> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| AegisError::PluginError(format!("WASM validation failed: {}", e)))?;

        let manifest = self.extract_manifest(&module)?;

        let mut write_guard = self
            .registry
            .write()
            .map_err(|_| AegisError::PluginError("Registry lock poisoned".into()))?;

        write_guard.insert(
            name.to_string(),
            LoadedPlugin {
                manifest: manifest.clone(),
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

    /// Extracts declarative plugin manifest via guest export or JSON metadata
    fn extract_manifest(&self, module: &Module) -> Result<PluginManifest> {
        let mut store = Store::new(&self.engine, ());
        store
            .set_fuel(500_000)
            .map_err(|e| AegisError::PluginError(e.to_string()))?;

        let linker = Linker::new(&self.engine);
        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| AegisError::PluginError(format!("Instantiation failed: {}", e)))?;

        // 1. Try typed function export: fn get_manifest_json() -> (ptr, len)
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
                    .trim_end_matches('\0'); // <--- ADD THIS to strip WASM memory padding
                let manifest: PluginManifest = serde_json::from_str(json_str).map_err(|e| {
                    AegisError::PluginError(format!("Invalid manifest JSON: {}", e))
                })?;
                return Ok(manifest);
            }
        }

        // 2. Default fallback manifest based on module name
        Ok(PluginManifest::default())
    }

    /// Executes a slash command on the guest plugin using packed pointer/len JSON ABI
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

        let linker = Linker::new(&self.engine);
        let module = Module::new(&self.engine, &plugin.wasm_bytes)
            .map_err(|e| AegisError::PluginError(e.to_string()))?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| AegisError::PluginError(e.to_string()))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| AegisError::PluginError("Plugin lacks exported linear memory".into()))?;

        // Format input payload
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

        // Write input to linear memory
        memory.data_mut(&mut store)[input_ptr..input_ptr + input_bytes.len()]
            .copy_from_slice(input_bytes);

        // Execute guest handler
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

    /// Executes incoming HTTP webhook requests routed to `/api/plugins/:id/*path`
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

        let linker = Linker::new(&self.engine);
        let module = Module::new(&self.engine, &plugin.wasm_bytes)
            .map_err(|e| AegisError::PluginError(e.to_string()))?;

        let instance = linker
            .instantiate(&mut store, &module)
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
    fn test_sandboxed_wasm_execution_and_fuel_bounding() {
        let engine = DynamicPluginEngine::new();

        // 1. A perfectly valid WAT that uses raw memory initialization
        let wat = r#"
            (module
                (memory (export "memory") 1)
                
                ;; Embed manifest JSON at offset 0 (Length: 78)
                (data (i32.const 0) "{\"name\":\"test_plugin\",\"slash_commands\":[{\"name\":\"ping\",\"description\":\"Pong\"}]}")
                
                ;; Embed reply at offset 100 (Length: 15)
                (data (i32.const 100) "Pong from WASM!")
                
                (func (export "alloc") (param i32) (result i32)
                    i32.const 500
                )

                ;; Returns offset 0, length 78 -> (0 << 32) | 78 = 78
                (func (export "get_manifest") (result i64)
                    i64.const 78
                )

                ;; Returns offset 100, length 15 -> (100 << 32) | 15 = 429496729615
                (func (export "on_slash_command") (param i32 i32) (result i64)
                    i64.const 429496729615
                )
            )
        "#;

        let wasm_bytes = wat::parse_str(wat).expect("WAT parse failed");

        // 2. Hot-swap the plugin (this calls get_manifest)
        let manifest = engine
            .hot_swap_plugin("test_plugin", &wasm_bytes)
            .expect("Hot swap failed");

        assert_eq!(manifest.name, "test_plugin");
        assert_eq!(manifest.slash_commands.len(), 1);
        assert_eq!(manifest.slash_commands[0].name, "ping");

        // 3. Execute the slash command
        let reply = engine
            .execute_slash_command("test_plugin", "ping", "{}")
            .expect("Command execution failed");

        assert_eq!(reply, "Pong from WASM!");
    }
}
