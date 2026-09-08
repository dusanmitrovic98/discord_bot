# 🛡️ Aegis Bastion (Sebastian The Butler)

An enterprise-grade, memory-sealed Discord defense engine written in **Rust**. Engineered specifically to eradicate predatory raid attacks, ban-evading accounts, and illicit/NSFW media across server joins, messages, and third-party bot embeds.

---

## ⚡ Architectural Highlights

- **In-Memory Zero-Rebuild Engine (`sentry_runner`):** Runs as an immutable PID 1 supervisor on Linux. Downloads compressed, Ed25519-signed core binaries from MongoDB Atlas, allocates anonymous memory descriptors via `memfd_create`, applies kernel seals (`F_ADD_SEALS`), and executes child cores in RAM. **Hot-swap updates take <1 second without rebuilding or restarting cloud containers.**
- **Adversarial Gatekeeper Pre-Filter (`src/gatekeeper.rs`):** A multi-pass canonicalization pipeline (Cyrillic/Greek visual homoglyph mapping, leetspeak transliteration, delimiter stripping, and duplicate collapsing) that neutralizes predatory usernames and nicknames in **<65 microseconds** with zero false positives on innocent gamers.
- **Sub-Millisecond Hash Caching:** Persistent SHA-256 and perceptual difference hashing (`dHash`) stored in MongoDB Atlas. Repeat malicious media is snuffed out in **<2ms** from cache, bypassing cloud vision APIs completely.
- **Bounded Concurrency Inference Queue:** A bounded Tokio MPSC worker queue that throttles image classification requests sequentially, preventing single-core / 512MB RAM cloud classifiers from experiencing Out-Of-Memory (OOM) crashes during heavy raid bursts.
- **Two-Tier Split Alerts:**
  - **Moderator Channel:** Clean text-only alerts. Moderators are notified without being subjected to toxic adult imagery.
  - **Audit Logs Channel:** Verbose incident reports with the exact evidence attached as a file for the Server Owner to review before taking manual administrative action.
- **Single-Tenant Lockdown:** Bound strictly to authorized Server IDs (`AUTHORIZED_GUILD_ID`). Auto-evicts itself from unauthorized servers and ignores external direct messages.

---

## 🏗️ System Architecture

```
[ Developer Workstation ]
       │
       ├── 1. Build & Sign Core (`cargo build --release --bin bot_core`)
       └── 2. Publish Blob to MongoDB Atlas (`titan_cli publish-core`)
                                  │
                                  ▼
                     [ MongoDB Atlas (Cloud) ]
                     ├── system_core_blob (Zstd + Ed25519)
                     ├── image_signatures (Blacklisted Hashes)
                     └── moderation_audit_log (Immutable Audit)
                                  │
                                  │  HTTP GET /update Trigger
                                  ▼
[ Render Cloud Container (512MB RAM) ]
┌────────────────────────────────────────────────────────────────────────┐
│  PID 1: Sentry Supervisor (sentry_runner)                              │
│   ├── Inbound HTTP Sentry (Health Check & /update trigger)             │
│   ├── Verifies Ed25519 Cryptographic Signature                         │
│   ├── Decompresses Zstd Binary in RAM                                  │
│   ├── Allocates Linux `memfd_create` & Applies F_SEAL_*                │
│   └── Spawns Child Core (Health Watchdog & LKG Rollback)               │
│                                                                        │
│  Child Process: Active Bot Core (bot_core)                             │
│   ├── Serenity Discord Gateway (Privileged Member & Message Intents)   │
│   ├── Text Gatekeeper (Instant Pre-Filter on Joins & Messages)         │
│   ├── Multi-Bot Embed Inspector (Mudae, Pokétwo, Sapphire, Bump Bots)  │
│   └── Bounded Sequential Worker Queue -> Render ViT SFW Classifier     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```
├── src/
│   ├── lib.rs                  # Domain error taxonomy and shared exports
│   ├── crypto.rs               # Ed25519 cryptographic signing & image hashing (SHA256, dHash)
│   ├── gatekeeper.rs           # Multi-pass text normalizer & regex heuristic engine
│   ├── queue.rs                # Bounded Tokio MPSC worker queue & resilient classifier client
│   ├── supervisor.rs           # Linux memfd_create RAM allocation, sealing, and watchdog rollback
│   ├── plugin_engine.rs        # Sandboxed WASM plugin runtime (Wasmtime) with fuel metering
│   ├── db.rs                   # MongoDB Atlas models, BSON storage, and audit logger
│   └── bot.rs                  # Serenity event handlers (joins, messages, dual alerts, diagnostics)
├── src/bin/
│   ├── sentry_runner.rs        # Immutable PID 1 Supervisor binary
│   ├── bot_core.rs             # Swappable Discord Bot Core binary
│   └── titan_cli.rs            # Workstation CLI: keygen, zstd-compression, and blob publishing
├── tests/
│   ├── integration_pipeline.rs # End-to-end multimodal pipeline verification
│   └── gatekeeper_pfp_deep_test.rs # 39-point adversarial evasion and PFP test battery
└── Cargo.toml                  # Workspace manifest with size-optimized release profiles
```

---

## ⚙️ Environment Variables

The system relies strictly on runtime environment variables (no `.env` files committed to disk):

| Variable | Description | Example |
| :--- | :--- | :--- |
| `DISCORD_TOKEN` | Discord Bot Token with Privileged Intents enabled | `MTAx...` |
| `MONGO_URI` | MongoDB Atlas Cloud Connection String | `mongodb+srv://user:pass@cluster.mongodb.net/?retryWrites=true&w=majority` |
| `CLASSIFIER_ENDPOINT` | ViT SFW Classifier Inference Endpoint | `https://sfw-classifier.onrender.com/api/classify` |
| `PORT` | Inbound port for Render health checks and `/update` | `10000` |

---

## 🚀 Workstation & Deployment Commands

### 1. Run the Full Adversarial Test Battery
Execute all 39 table-driven adversarial evasion tests and PFP hashing suites:
```bash
cargo test --test gatekeeper_pfp_deep_test -- --nocapture
```

### 2. Generate Your Ed25519 Release Keypair
```bash
cargo run --bin titan_cli keygen
```

### 3. Build & Publish a New Core Binary to MongoDB
```bash
cargo build --release --bin bot_core
cargo run --bin titan_cli publish-core ./target/release/bot_core <YOUR_PRIVATE_KEY_HEX>
```

### 4. Trigger In-Memory Hot-Swap (Zero Downtime)
```bash
curl http://localhost:10000/update
# On Render: curl https://<your-render-service>.onrender.com/update
```

---

## 🧪 Live Discord Diagnostic Commands

Administrators can safely test filters in any channel without risking accidental account bans:

- `$test-name <any string>`: Runs the 3-pass Gatekeeper on any username or nickname string, outputting the normalized form, alphanumeric projection, deduplicated projection, and whether it triggers an instant ban.
- `$test-pfp [@user or attachment]`: Downloads the specified avatar, generates its SHA-256 hash, checks Atlas cache status, executes the ViT classifier, and prints exact Safe/NSFW confidence percentages and inference latency.

---

## ⚖️ Operational Rules of Engagement

1. **Predatory Usernames/Nicknames:** Eradicated immediately via **permanent ban** on join or on message send (7-day message purge).
2. **Adult Images & Embeds:** Messages and third-party bot embeds are **deleted immediately**, the media hash is permanently blacklisted, and alerts are dispatched. **The user is NOT automatically banned**, giving server owners human discretion to audit the evidence.
3. **NSFW Profile Pictures:** Users holding blacklisted adult avatars have their chat messages **automatically blocked** until they change their avatar back to a safe image.

---

## 🛡️ License & Mission

Designed and maintained for absolute server sovereignty and protection against predatory online actors under the Law of Good.
