use chrono::Utc;
use ed25519_dalek::SigningKey;
use mongodb::bson::{doc, spec::BinarySubtype, Binary, Document};
use mongodb::Client;
use rand::rngs::OsRng;
use std::env;
use std::fs;

use aegis_bastion::crypto::CryptoEngine;
use aegis_bastion::Result;

#[derive(Debug, PartialEq, Eq)]
enum CliAction {
    Keygen,
    PublishCore { file_path: String, key_hex: String },
    PublishPlugin { file_path: String, name: String },
}

impl CliAction {
    fn parse(args: &[String]) -> std::result::Result<Self, String> {
        if args.len() < 2 {
            return Err("Insufficient arguments".into());
        }

        match args[1].as_str() {
            "keygen" => Ok(CliAction::Keygen),
            "publish-core" => {
                if args.len() < 4 {
                    Err("Usage: titan_cli publish-core <binary_path> <key_hex>".into())
                } else {
                    Ok(CliAction::PublishCore {
                        file_path: args[2].clone(),
                        key_hex: args[3].clone(),
                    })
                }
            }
            "publish-plugin" => {
                if args.len() < 4 {
                    Err("Usage: titan_cli publish-plugin <wasm_path> <name>".into())
                } else {
                    Ok(CliAction::PublishPlugin {
                        file_path: args[2].clone(),
                        name: args[3].clone(),
                    })
                }
            }
            other => Err(format!("Unknown command: '{}'", other)),
        }
    }
}

fn exec_keygen() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let priv_bytes = signing_key.to_bytes();
    let pub_bytes = verifying_key.to_bytes();

    println!("\n=== ARCHITECT ED25519 MASTER KEYPAIR GENERATED ===");
    println!(
        "\n[PRIVATE KEY] (Workstation Only):\n{}",
        hex::encode(priv_bytes)
    );
    println!("\n[PUBLIC KEY] (Hex):\n{}", hex::encode(pub_bytes));
    println!("\n[PUBLIC KEY] (Rust array for sentry_runner.rs):");
    print!("const ARCHITECT_PUBLIC_KEY: [u8; 32] = [\n    ");
    for (i, b) in pub_bytes.iter().enumerate() {
        print!("0x{:02x}", b);
        if i < 31 {
            print!(", ");
            if (i + 1) % 8 == 0 {
                print!("\n    ");
            }
        }
    }
    println!("\n];\n");
}

async fn exec_publish_core(client: &Client, file_path: &str, key_hex: &str) -> Result<()> {
    let raw_binary = fs::read(file_path)?;
    let compressed = zstd::encode_all(&raw_binary[..], 19)?;
    println!(
        "Compressed binary from {} bytes to {} bytes.",
        raw_binary.len(),
        compressed.len()
    );

    let key_bytes =
        hex::decode(key_hex).map_err(|e| aegis_bastion::AegisError::ConfigError(e.to_string()))?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| aegis_bastion::AegisError::ConfigError("Key must be 32 bytes".into()))?;

    let signature = CryptoEngine::sign_data(&key_array, &compressed);
    let sha256 = CryptoEngine::sha256(&compressed);

    let coll = client
        .database("aegis_bastion")
        .collection::<Document>("system_core_blob");
    coll.insert_one(doc! {
        "version": "1.0.0",
        "compressed_binary": Binary { subtype: BinarySubtype::Generic, bytes: compressed },
        "signature": Binary { subtype: BinarySubtype::Generic, bytes: signature.to_vec() },
        "sha256": sha256,
        "deployed_at": Utc::now()
    })
    .await?;

    println!("Core binary blob successfully signed and published to MongoDB Atlas!");
    Ok(())
}

async fn exec_publish_plugin(client: &Client, file_path: &str, plugin_name: &str) -> Result<()> {
    let wasm_bytes = fs::read(file_path)?;
    let sha256 = CryptoEngine::sha256(&wasm_bytes);

    // Validate WASM and extract manifest automatically
    let engine = aegis_bastion::plugin_engine::DynamicPluginEngine::new();
    let manifest = engine
        .hot_swap_plugin(plugin_name, &wasm_bytes)
        .unwrap_or_default();
    let manifest_json = serde_json::to_string(&manifest).unwrap_or_default();

    let coll = client
        .database("aegis_bastion")
        .collection::<Document>("plugins");
    coll.delete_many(doc! { "name": plugin_name }).await?;
    coll.insert_one(doc! {
        "name": plugin_name,
        "manifest_json": manifest_json,
        "bytecode": Binary { subtype: BinarySubtype::Generic, bytes: wasm_bytes },
        "sha256": sha256,
        "enabled": true,
        "updated_at": Utc::now()
    })
    .await?;

    println!(
        "Plugin '{}' (Commands: {}) published to MongoDB Atlas successfully!",
        plugin_name,
        manifest.slash_commands.len()
    );
    Ok(())
}

fn print_usage() {
    println!("Usage:");
    println!("  titan_cli keygen");
    println!("  titan_cli publish-core <binary_path> <key_hex>");
    println!("  titan_cli publish-plugin <wasm_path> <name>");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let action = match CliAction::parse(&args) {
        Ok(act) => act,
        Err(e) => {
            println!("Error: {}", e);
            print_usage();
            return;
        }
    };

    if action == CliAction::Keygen {
        exec_keygen();
        return;
    }

    let mongo_uri = env::var("MONGO_URI").expect("MONGO_URI environment variable required");
    let client = Client::with_uri_str(&mongo_uri)
        .await
        .expect("MongoDB connection failed");

    match action {
        CliAction::PublishCore { file_path, key_hex } => {
            if let Err(e) = exec_publish_core(&client, &file_path, &key_hex).await {
                eprintln!("Publish core failed: {}", e);
            }
        }
        CliAction::PublishPlugin { file_path, name } => {
            if let Err(e) = exec_publish_plugin(&client, &file_path, &name).await {
                eprintln!("Publish plugin failed: {}", e);
            }
        }
        CliAction::Keygen => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_action_parser() {
        let args_keygen = vec!["bin".into(), "keygen".into()];
        assert_eq!(CliAction::parse(&args_keygen), Ok(CliAction::Keygen));

        let args_core = vec![
            "bin".into(),
            "publish-core".into(),
            "bot.bin".into(),
            "abcd".into(),
        ];
        assert_eq!(
            CliAction::parse(&args_core),
            Ok(CliAction::PublishCore {
                file_path: "bot.bin".into(),
                key_hex: "abcd".into()
            })
        );

        let args_invalid = vec!["bin".into(), "unknown-cmd".into()];
        assert!(CliAction::parse(&args_invalid).is_err());
    }
}
