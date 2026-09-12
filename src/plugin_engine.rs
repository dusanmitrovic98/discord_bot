//! # Dynamic WebAssembly Plugin Engine
//!
//! Sandboxed microkernel executing community WASM plugins via Wasmtime.
//! Features fuel bounding (NASA Rule 2), module pre-compilation, host entropy,
//! gateway event multiplexing, and isolated namespaced KV persistence with storage quotas.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::info;
use wasmtime::*;

use crate::db::DatabaseEngine;
use crate::{AegisError, Result};

pub const DEFAULT_STORAGE_QUOTA_BYTES: u64 = 256 * 1024; // 256KB default grant
pub const MAX_STORAGE_CEILING_BYTES: u64 = 10 * 1024 * 1024; // 10MB hard upper bound

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
    pub requested_storage_bytes: u64, // Declared storage quota
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
            requested_storage_bytes: DEFAULT_STORAGE_QUOTA_BYTES,
        }
    }
}

pub struct LoadedPlugin {
    pub manifest: PluginManifest,
    pub module: Module,
    pub wasm_bytes: Vec<u8>,
    pub allocated_storage_bytes: u64,
}

/// Execution context injected into each guest store
pub struct PluginContext {
    pub plugin_name: String,
    pub allocated_storage_bytes: u64,
    pub db: Option<Arc<DatabaseEngine>>,
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
        config.consume_fuel(true);
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

    pub fn is_bytecode_identical(&self, name: &str, new_bytes: &[u8]) -> bool {
        let guard = match self.registry.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        if let Some(existing) = guard.get(name) {
            existing.wasm_bytes == new_bytes
        } else {
            false
        }
    }

    /// Builds Linker with host entropy AND namespaced KV storage bridge (NASA Rule 2 & 5)
    fn build_linker(&self) -> Result<Linker<PluginContext>> {
        let mut linker = Linker::new(&self.engine);

        // 1. Host Entropy (CSPRNG)
        linker
            .func_wrap("env", "host_random_u32", || -> u32 {
                rand::random::<u32>()
            })
            .map_err(|e| {
                AegisError::PluginError(format!("Failed registering host_random_u32: {}", e))
            })?;

        // 2. Namespaced Storage: host_kv_set(key_ptr, key_len, val_ptr, val_len) -> i32
        linker
            .func_wrap(
                "env",
                "host_kv_set",
                |mut caller: Caller<'_, PluginContext>,
                 key_ptr: i32,
                 key_len: i32,
                 val_ptr: i32,
                 val_len: i32|
                 -> i32 {
                    let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return -1,
                    };

                    let (kp, kl) = (key_ptr as usize, key_len as usize);
                    let (vp, vl) = (val_ptr as usize, val_len as usize);
                    let mem = memory.data(&caller);

                    if kp + kl > mem.len() || vp + vl > mem.len() {
                        return -1; // Out-of-bounds pointer
                    }

                    // Enforce allocated storage quota (NASA Rule 2)
                    let total_write_bytes = (kl + vl) as u64;
                    if total_write_bytes > caller.data().allocated_storage_bytes {
                        return -4; // Quota exceeded
                    }

                    let key_str = match std::str::from_utf8(&mem[kp..kp + kl]) {
                        Ok(s) => s.to_string(),
                        Err(_) => return -2, // Invalid UTF-8
                    };
                    let val_str = match std::str::from_utf8(&mem[vp..vp + vl]) {
                        Ok(s) => s.to_string(),
                        Err(_) => return -2,
                    };

                    let plugin_name = caller.data().plugin_name.clone();
                    if let Some(db) = caller.data().db.clone() {
                        tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(async {
                                let _ = db.plugin_kv_set(&plugin_name, &key_str, &val_str).await;
                            });
                        });
                        0 // Success
                    } else {
                        -3 // DB unavailable
                    }
                },
            )
            .map_err(|e| {
                AegisError::PluginError(format!("Failed registering host_kv_set: {}", e))
            })?;

        // 3. Namespaced Storage: host_kv_get(key_ptr, key_len) -> i64 (packed ptr/len)
        linker
            .func_wrap(
                "env",
                "host_kv_get",
                |mut caller: Caller<'_, PluginContext>, key_ptr: i32, key_len: i32| -> i64 {
                    let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return 0,
                    };

                    let (kp, kl) = (key_ptr as usize, key_len as usize);
                    let mem = memory.data(&caller);
                    if kp + kl > mem.len() {
                        return 0;
                    }

                    let key_str = match std::str::from_utf8(&mem[kp..kp + kl]) {
                        Ok(s) => s.to_string(),
                        Err(_) => return 0,
                    };

                    let plugin_name = caller.data().plugin_name.clone();
                    let val_opt = if let Some(db) = caller.data().db.clone() {
                        tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(async {
                                db.plugin_kv_get(&plugin_name, &key_str)
                                    .await
                                    .unwrap_or(None)
                            })
                        })
                    } else {
                        None
                    };

                    let val_str = match val_opt {
                        Some(v) => v,
                        None => return 0, // Key not found
                    };

                    let val_bytes = val_str.as_bytes();
                    let alloc_fn = match caller.get_export("alloc").and_then(|e| e.into_func()) {
                        Some(f) => match f.typed::<i32, i32>(&caller) {
                            Ok(tf) => tf,
                            Err(_) => return 0,
                        },
                        None => return 0,
                    };

                    let out_ptr = match alloc_fn.call(&mut caller, val_bytes.len() as i32) {
                        Ok(p) => p as usize,
                        Err(_) => return 0,
                    };

                    let mut mem_mut =
                        match caller.get_export("memory").and_then(|e| e.into_memory()) {
                            Some(m) => m,
                            None => return 0,
                        };

                    let data = mem_mut.data_mut(&mut caller);
                    if out_ptr + val_bytes.len() <= data.len() {
                        data[out_ptr..out_ptr + val_bytes.len()].copy_from_slice(val_bytes);
                        ((out_ptr as i64) << 32) | (val_bytes.len() as i64)
                    } else {
                        0
                    }
                },
            )
            .map_err(|e| {
                AegisError::PluginError(format!("Failed registering host_kv_get: {}", e))
            })?;

        Ok(linker)
    }

    pub fn hot_swap_plugin(&self, name: &str, wasm_bytes: &[u8]) -> Result<PluginManifest> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| AegisError::PluginError(format!("WASM compilation failed: {}", e)))?;

        let manifest = self.extract_manifest(&module)?;

        // Determine storage allocation: default 256KB or approved requested quota
        let allocated_storage = if manifest.requested_storage_bytes <= DEFAULT_STORAGE_QUOTA_BYTES {
            manifest.requested_storage_bytes
        } else {
            DEFAULT_STORAGE_QUOTA_BYTES // Clamped to baseline until approved by Owner
        };

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
                allocated_storage_bytes: allocated_storage,
            },
        );

        info!(
            "WASM Plugin '{}' (v{}) loaded in memory. Storage: {}KB",
            manifest.name,
            manifest.version,
            allocated_storage / 1024
        );
        Ok(manifest)
    }

    pub fn unload_plugin(&self, name: &str) {
        if let Ok(mut write_guard) = self.registry.write() {
            if write_guard.remove(name).is_some() {
                info!("WASM Plugin '{}' unloaded from memory.", name);
            }
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

    pub fn dispatch_event(&self, event_name: &str, payload_json: &str) {
        let plugins: Vec<(String, Module, Vec<String>, u64)> = match self.registry.read() {
            Ok(guard) => guard
                .iter()
                .map(|(name, p)| {
                    (
                        name.clone(),
                        p.module.clone(),
                        p.manifest.subscribed_events.clone(),
                        p.allocated_storage_bytes,
                    )
                })
                .collect(),
            Err(_) => return,
        };

        for (name, module, subscriptions, quota) in plugins {
            if !subscriptions.iter().any(|e| e == event_name || e == "*") {
                continue;
            }

            let engine_clone = self.clone();
            let event_name = event_name.to_string();
            let payload = payload_json.to_string();

            tokio::spawn(async move {
                let timeout_res = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    engine_clone.execute_event_sync(&name, &module, &event_name, &payload, quota),
                )
                .await;

                if timeout_res.is_err() {
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
        plugin_name: &str,
        module: &Module,
        event_name: &str,
        payload_json: &str,
        quota: u64,
    ) -> Result<()> {
        let ctx = PluginContext {
            plugin_name: plugin_name.to_string(),
            allocated_storage_bytes: quota,
            db: self.db.clone(),
        };

        let mut store = Store::new(&self.engine, ctx);
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
        let ctx = PluginContext {
            plugin_name: "manifest_probe".to_string(),
            allocated_storage_bytes: DEFAULT_STORAGE_QUOTA_BYTES,
            db: None,
        };

        let mut store = Store::new(&self.engine, ctx);
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

        let ctx = PluginContext {
            plugin_name: plugin_name.to_string(),
            allocated_storage_bytes: plugin.allocated_storage_bytes,
            db: self.db.clone(),
        };

        let mut store = Store::new(&self.engine, ctx);
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

        let ctx = PluginContext {
            plugin_name: plugin_name.to_string(),
            allocated_storage_bytes: plugin.allocated_storage_bytes,
            db: self.db.clone(),
        };

        let mut store = Store::new(&self.engine, ctx);
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
