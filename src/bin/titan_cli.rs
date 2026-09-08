use aegis_bastion::crypto::CryptoEngine;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use mongodb::{
    bson::{doc, spec::BinarySubtype, Binary, Document},
    Client,
};
use rand::rngs::OsRng;
use std::env;
use std::fs;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let command = &args[1];

    // ==========================================
    // KEYGEN ROUTINE (Does not require MongoDB)
    // ==========================================
    if command == "keygen" {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let priv_bytes = signing_key.to_bytes();
        let pub_bytes = verifying_key.to_bytes();

        println!("\n=== ARCHITECT ED25519 MASTER KEYPAIR GENERATED ===");
        println!("\n[PRIVATE KEY] (Save this securely on your workstation!):");
        println!("{}", hex::encode(priv_bytes));

        println!("\n[PUBLIC KEY] (Hex):");
        println!("{}", hex::encode(pub_bytes));

        println!("\n[PUBLIC KEY] (Rust array - paste this into src/bin/sentry_runner.rs):");
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
        return;
    }

    // ==========================================
    // MONGODB COMMANDS (publish-core, publish-plugin)
    // ==========================================
    if args.len() < 4 {
        print_usage();
        return;
    }

    let file_path = &args[2];
    let mongo_uri =
        env::var("MONGO_URI").expect("MONGO_URI environment variable required for publishing");
    let client = Client::with_uri_str(&mongo_uri)
        .await
        .expect("DB connection failed");
    let db = client.database("aegis_bastion");

    match command.as_str() {
        "publish-core" => {
            let signing_key_hex = &args[3];
            let raw_binary = fs::read(file_path).expect("Could not read binary file");

            // 1. Compress binary with zstd
            let compressed =
                zstd::encode_all(&raw_binary[..], 19).expect("Zstd compression failed");
            println!(
                "Compressed binary from {} bytes to {} bytes.",
                raw_binary.len(),
                compressed.len()
            );

            // 2. Sign with Ed25519 private key
            let key_bytes = hex::decode(signing_key_hex).expect("Invalid hex key");
            let key_array: [u8; 32] = key_bytes.try_into().expect("Key must be 32 bytes");
            let signature = CryptoEngine::sign_data(&key_array, &compressed);
            let sha256 = CryptoEngine::sha256(&compressed);

            // 3. Upload to MongoDB system_core_blob directly
            let coll = db.collection::<Document>("system_core_blob");
            coll.insert_one(doc! {
                "version": "1.0.0",
                "compressed_binary": Binary { subtype: BinarySubtype::Generic, bytes: compressed },
                "signature": Binary { subtype: BinarySubtype::Generic, bytes: signature.to_vec() },
                "sha256": sha256,
                "deployed_at": Utc::now()
            })
            .await
            .expect("Failed to upload blob to MongoDB");

            println!("Core binary blob successfully signed and published to MongoDB!");
        }
        "publish-plugin" => {
            let plugin_name = &args[3];
            let wasm_bytes = fs::read(file_path).expect("Could not read WASM file");
            let sha256 = CryptoEngine::sha256(&wasm_bytes);

            let coll = db.collection::<Document>("plugins");
            coll.insert_one(doc! {
                "name": plugin_name,
                "bytecode": Binary { subtype: BinarySubtype::Generic, bytes: wasm_bytes },
                "sha256": sha256,
                "enabled": true,
                "updated_at": Utc::now()
            })
            .await
            .expect("Failed to upload plugin to MongoDB");

            println!(
                "Plugin '{}' published to MongoDB successfully!",
                plugin_name
            );
        }
        _ => print_usage(),
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  titan_cli keygen");
    println!("  titan_cli publish-core <binary_path> <private_key_hex>");
    println!("  titan_cli publish-plugin <wasm_path> <plugin_name>");
}
