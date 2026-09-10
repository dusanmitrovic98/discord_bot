use aegis_bastion::crypto::CryptoEngine;
use aegis_bastion::gatekeeper::{TextGatekeeper, ThreatVerdict};
use aegis_bastion::plugin_engine::DynamicPluginEngine;

#[test]
fn test_multimodal_defense_pipeline() {
    // 1. Text Gatekeeper intercepts predatory patterns
    let gatekeeper = TextGatekeeper::new();
    assert_eq!(
        gatekeeper.evaluate_threat("cpstuff08143"),
        ThreatVerdict::InstantBan
    );
    assert_eq!(
        gatekeeper.evaluate_threat("MEGA-LINK-08225"),
        ThreatVerdict::InstantBan
    );
    assert_eq!(
        gatekeeper.evaluate_threat("legitimate_user_42"),
        ThreatVerdict::Safe
    );

    // 2. Cryptographic signature and tamper proofing
    let signing_key = [7u8; 32];
    let public_key = ed25519_dalek::SigningKey::from_bytes(&signing_key)
        .verifying_key()
        .to_bytes();
    let payload = b"simulated_bot_core_binary";
    let signature = CryptoEngine::sign_data(&signing_key, payload);

    assert!(CryptoEngine::verify_signature(&public_key, payload, &signature).is_ok());

    // 3. Dynamic WASM Plugin ABI (Microkernel JSON Payload Test)
    let engine = DynamicPluginEngine::new();

    let wat = r#"
        (module
            (memory (export "memory") 1)
            (data (i32.const 0) "{\"name\":\"test_plugin\",\"slash_commands\":[{\"name\":\"ping\",\"description\":\"Pong\"}]}")
            (data (i32.const 100) "Pong from WASM!")
            (func (export "alloc") (param i32) (result i32)
                i32.const 500
            )
            (func (export "get_manifest") (result i64)
                i64.const 78
            )
            (func (export "on_slash_command") (param i32 i32) (result i64)
                i64.const 429496729615
            )
        )
    "#;
    let wasm = wat::parse_str(wat).unwrap();
    let manifest = engine.hot_swap_plugin("test_plugin", &wasm).unwrap();

    assert_eq!(manifest.name, "test_plugin");

    let reply = engine
        .execute_slash_command("test_plugin", "ping", "{}")
        .unwrap();
    assert_eq!(reply, "Pong from WASM!");
}
