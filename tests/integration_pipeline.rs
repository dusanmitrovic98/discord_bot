use aegis_bastion::crypto::CryptoEngine;
use aegis_bastion::gatekeeper::TextGatekeeper;
use aegis_bastion::plugin_engine::{DynamicPluginEngine, PluginContext};

#[test]
fn test_multimodal_defense_pipeline() {
    // 1. Text Gatekeeper intercepts predatory patterns
    let gatekeeper = TextGatekeeper::new();
    assert!(gatekeeper.is_flagged("cpstuff08143"));
    assert!(gatekeeper.is_flagged("MEGA-LINK-08225"));
    assert!(!gatekeeper.is_flagged("legitimate_user_42"));

    // 2. Cryptographic signature and tamper proofing
    let signing_key = [7u8; 32];
    let public_key = ed25519_dalek::SigningKey::from_bytes(&signing_key)
        .verifying_key()
        .to_bytes();
    let payload = b"simulated_bot_core_binary";
    let signature = CryptoEngine::sign_data(&signing_key, payload);

    assert!(CryptoEngine::verify_signature(&public_key, payload, &signature).is_ok());

    // 3. Dynamic WASM Plugin hot-swap and interception
    let plugin_engine = DynamicPluginEngine::new();
    let wat = r#"
        (module
            (func (export "evaluate") (param i32) (result i32)
                local.get 0
                i32.const 5
                i32.gt_s
            )
        )
    "#;
    let wasm = wat::parse_str(wat).unwrap();
    plugin_engine.hot_swap_plugin("test_filter", &wasm).unwrap();

    let mut ctx = PluginContext {
        user_id: 1,
        content: "exceeds_five".into(),
        is_actionable: false,
    };
    plugin_engine.evaluate_all(&mut ctx).unwrap();
    assert!(ctx.is_actionable);
}
