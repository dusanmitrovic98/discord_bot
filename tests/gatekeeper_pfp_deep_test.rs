use aegis_bastion::crypto::CryptoEngine;
use aegis_bastion::gatekeeper::TextGatekeeper;
use image::{ImageBuffer, Rgb};
use std::io::Cursor;
use std::time::Instant;

#[allow(dead_code)]
struct TestCase {
    name: &'static str,
    input: &'static str,
    expected_flagged: bool,
    category: &'static str,
}

#[test]
fn test_gatekeeper_comprehensive_adversarial_battery() {
    let gatekeeper = TextGatekeeper::new();

    let cases = vec![
        TestCase { name: "Raid Acc 1", input: "megalink08225", expected_flagged: true, category: "Raid Exact" },
        TestCase { name: "Raid Acc 2", input: "cpstuuf", expected_flagged: true, category: "Raid Exact" },
        TestCase { name: "Raid Acc 3", input: "megalink08816", expected_flagged: true, category: "Raid Exact" },
        TestCase { name: "Raid Acc 4", input: "megalink0588", expected_flagged: true, category: "Raid Exact" },
        TestCase { name: "Raid Acc 5", input: "cpstuff08143", expected_flagged: true, category: "Raid Exact" },
        TestCase { name: "Raid Acc 6", input: "megalinkstuff0680", expected_flagged: true, category: "Raid Exact" },

        TestCase { name: "Vowel stretch 1", input: "cpstuuuuf", expected_flagged: true, category: "Stretching" },
        TestCase { name: "Vowel stretch 2", input: "cpstuuuuuuuffff", expected_flagged: true, category: "Stretching" },
        TestCase { name: "Consonant stretch 1", input: "c.p. sttufff", expected_flagged: true, category: "Stretching" },
        TestCase { name: "Word stretch", input: "mmmeeegggaaallliinnkk", expected_flagged: true, category: "Stretching" },
        TestCase { name: "Single f variation", input: "cpstuf", expected_flagged: true, category: "Stretching" },

        TestCase { name: "Hyphen padded", input: "M-E-G-A---L-I-N-K", expected_flagged: true, category: "Delimiters" },
        TestCase { name: "Underscore padded", input: "m_e_g_a_l_i_n_k", expected_flagged: true, category: "Delimiters" },
        TestCase { name: "Dot padded", input: "c.p...s.t.u.f.f", expected_flagged: true, category: "Delimiters" },
        TestCase { name: "Mixed separators", input: "c-p._.stuff", expected_flagged: true, category: "Delimiters" },
        TestCase { name: "Tilde & spaces", input: "c ~ p ~ stuff", expected_flagged: true, category: "Delimiters" },

        TestCase { name: "Zero-width space", input: "m\u{200B}e\u{200B}g\u{200B}a\u{200B}l\u{200B}i\u{200B}n\u{200B}k", expected_flagged: true, category: "Invisible Chars" },
        TestCase { name: "Zero-width joiner", input: "c\u{200D}p\u{200D}s\u{200D}t\u{200D}u\u{200D}f\u{200D}f", expected_flagged: true, category: "Invisible Chars" },
        TestCase { name: "Byte-order mark", input: "\u{FEFF}cpstuff\u{FEFF}", expected_flagged: true, category: "Invisible Chars" },

        TestCase { name: "Cyrillic Es and Er", input: "СР stuff", expected_flagged: true, category: "Homoglyphs" },
        TestCase { name: "Mixed Cyrillic text", input: "СР ѕтυff", expected_flagged: true, category: "Homoglyphs" },
        TestCase { name: "Full-width Japanese/Unicode", input: "ｍｅｇａ ｌｉｎｋ", expected_flagged: true, category: "Homoglyphs" },
        TestCase { name: "Cyrillic 'a' and 'o'", input: "megаlink", expected_flagged: true, category: "Homoglyphs" },

        TestCase { name: "Standard 1337", input: "m3g4 l1nk", expected_flagged: true, category: "Leetspeak" },
        TestCase { name: "Zero for O", input: "megalink08225", expected_flagged: true, category: "Leetspeak" },
        TestCase { name: "Dollar and At", input: "cp_@_stuff", expected_flagged: true, category: "Leetspeak" },
        TestCase { name: "Numeric suffix", input: "cpstuff9999", expected_flagged: true, category: "Leetspeak" },
        TestCase { name: "Alphanumeric mix", input: "M3G4_L1NK_STUFF", expected_flagged: true, category: "Leetspeak" },

        TestCase { name: "Normal gamer", input: "normal_gamer_guy", expected_flagged: false, category: "Benign Immunity" },
        TestCase { name: "Quokka benign", input: "bubbly_quokka_34489", expected_flagged: false, category: "Benign Immunity" },
        TestCase { name: "Peacock (has 'p', 'c')", input: "stylish_peacock_82532", expected_flagged: false, category: "Benign Immunity" },
        TestCase { name: "James Access", input: "jamesaccess0570", expected_flagged: false, category: "Benign Immunity" },
        TestCase { name: "Contains 'recipe'", input: "chef_secret_recipe", expected_flagged: false, category: "Benign Immunity" },
        TestCase { name: "Contains 'captain'", input: "captain_america_2026", expected_flagged: false, category: "Benign Immunity" },
        TestCase { name: "Contains 'escape'", input: "escape_from_tarkov", expected_flagged: false, category: "Benign Immunity" },
        TestCase { name: "Contains 'description'", input: "job_description_hr", expected_flagged: false, category: "Benign Immunity" },
        TestCase { name: "Contains 'mega_man'", input: "mega_man_classic_fan", expected_flagged: false, category: "Benign Immunity" },
        TestCase { name: "Permuted letters", input: "cstuffp", expected_flagged: false, category: "Benign Immunity" },
        TestCase { name: "Benign space pirate", input: "space_pirate_captain", expected_flagged: false, category: "Benign Immunity" },
    ];

    let mut passed = 0;
    let total = cases.len();
    let start_time = Instant::now();

    for case in &cases {
        let actual = gatekeeper.is_flagged(case.input);
        assert_eq!(
            actual, case.expected_flagged,
            "FAILED: Test '{}' with input '{}'",
            case.name, case.input
        );
        passed += 1;
    }

    let elapsed = start_time.elapsed();
    println!("HARDCODED RESULTS: {}/{} tests passed in {:.2?}", passed, total, elapsed);
}

#[test]
fn test_dynamic_audit_log_threat_rules_battery() {
    let gatekeeper = TextGatekeeper::new();

    let ban_rules = vec![
        r"(?i)m+e+g+a+.*(g+r+o+u+p+|s+e+l+l+|s+e+l+l+e+r+|v+i+d+|s+h+a+r+e+|d+r+i+v+e+)".to_string(),
        r"(?i)(g+o+o+d+|l+e+g+i+t+|r+e+a+l+|b+e+s+t+|c+h+e+a+p+|f+r+e+s+h+|n+e+w+)[\W_]*s+t+u+f+f+".to_string(),
        r"(?i)(t+e+l+e+g+r+a+m+|t+\.m+e+|t+e+l+e+)[\W_]*(c+h+a+t+|g+r+o+u+p+|l+i+n+k+|j+o+i+n+|c+h+a+n+n+e+l+)".to_string(),
    ];
    let delete_rules = vec![
        r"(?i)(d+i+s+c+o+r+d+|s+t+e+a+m+).*?(g+i+f+t+|n+i+t+r+o+|f+r+e+e+|a+i+r+d+r+o+p+)".to_string(),
    ];

    gatekeeper.reload_dynamic_rules(&ban_rules, &delete_rules).expect("Dynamic rules must compile");

    let dynamic_cases = vec![
        TestCase { name: "Audit: megagroup", input: "megagroup0982", expected_flagged: true, category: "Audit Log Raids" },
        TestCase { name: "Audit: goodstuff 1", input: "goodstuff0472", expected_flagged: true, category: "Audit Log Raids" },
        TestCase { name: "Audit: goodstuff 2", input: "goodstuff06783", expected_flagged: true, category: "Audit Log Raids" },
        TestCase { name: "Audit: legitstuff", input: "legitstuff0244", expected_flagged: true, category: "Audit Log Raids" },
        TestCase { name: "Audit: latestmegaseller", input: "latestmegaseller", expected_flagged: true, category: "Audit Log Raids" },
        TestCase { name: "Audit: megalinkseller", input: "megalinkseller0640", expected_flagged: true, category: "Audit Log Raids" },

        TestCase { name: "Cheapstuff variation", input: "cheapstuff99", expected_flagged: true, category: "Vendor Camouflage" },
        TestCase { name: "Freshstuff variation", input: "freshstuff42", expected_flagged: true, category: "Vendor Camouflage" },
        TestCase { name: "Newstuff variation", input: "newstuff2026", expected_flagged: true, category: "Vendor Camouflage" },
        TestCase { name: "Realstuff variation", input: "realstuff0912", expected_flagged: true, category: "Vendor Camouflage" },
        TestCase { name: "Beststuff variation", input: "beststuff99", expected_flagged: true, category: "Vendor Camouflage" },
        TestCase { name: "Stretched goodstuff", input: "gooooodstuuuffff888", expected_flagged: true, category: "Vendor Camouflage" },
        TestCase { name: "Delimiter goodstuff", input: "good_stuff_1234", expected_flagged: true, category: "Vendor Camouflage" },
        TestCase { name: "Hyphen legitstuff", input: "legit-stuff-5678", expected_flagged: true, category: "Vendor Camouflage" },
        TestCase { name: "Dot separated stuff", input: "real.stuff.42", expected_flagged: true, category: "Vendor Camouflage" },
        TestCase { name: "Leetspeak goodstuff", input: "g00dstuff0472", expected_flagged: true, category: "Vendor Camouflage" },
        TestCase { name: "Leetspeak legitstuff", input: "l3gitstuff0244", expected_flagged: true, category: "Vendor Camouflage" },

        TestCase { name: "Megagroup underscore", input: "mega_group_2026", expected_flagged: true, category: "Mega Variants" },
        TestCase { name: "Megaseller dot", input: "mega.seller.01", expected_flagged: true, category: "Mega Variants" },
        TestCase { name: "Megadrive variant", input: "megadrive_vault99", expected_flagged: true, category: "Mega Variants" },
        TestCase { name: "Megashare variant", input: "megashare_pack01", expected_flagged: true, category: "Mega Variants" },
        TestCase { name: "Leetspeak megagroup", input: "m3g4gr0up0982", expected_flagged: true, category: "Mega Variants" },

        TestCase { name: "T.me invite link", input: "t.me/join_chat_99", expected_flagged: true, category: "Telegram Funnels" },
        TestCase { name: "Telegram group bait", input: "telegram_group_link", expected_flagged: true, category: "Telegram Funnels" },
        TestCase { name: "Tele channel invite", input: "tele_channel_join", expected_flagged: true, category: "Telegram Funnels" },

        TestCase { name: "Discord nitro free", input: "discord_nitro_free_gift", expected_flagged: true, category: "Scam Bait" },
        TestCase { name: "Steam airdrop link", input: "steam_airdrop_free_gift", expected_flagged: true, category: "Scam Bait" },

        TestCase { name: "Megan (girl name)", input: "megan_fox_fan", expected_flagged: false, category: "False Positive Immunity" },
        TestCase { name: "Megan with numbers", input: "megan172028", expected_flagged: false, category: "False Positive Immunity" },
        TestCase { name: "Megabyte tech name", input: "megabyte_coder", expected_flagged: false, category: "False Positive Immunity" },
        TestCase { name: "Good game player", input: "good_game_bro", expected_flagged: false, category: "False Positive Immunity" },
        TestCase { name: "Thanksgiving stuffing", input: "stuffing_turkey_chef", expected_flagged: false, category: "False Positive Immunity" },
        TestCase { name: "Legitimate businessman", input: "legitimate_ceo", expected_flagged: false, category: "False Positive Immunity" },
        TestCase { name: "Steampunk gamer", input: "steampunk_automaton", expected_flagged: false, category: "False Positive Immunity" },
        TestCase { name: "Audit: okkotsu (Anime)", input: "okkotsu_yutadamaki", expected_flagged: false, category: "False Positive Immunity" },
        TestCase { name: "Audit: shikatsuki (Anime)", input: "shikatsuki0954", expected_flagged: false, category: "False Positive Immunity" },
        TestCase { name: "Audit: kavyansh (Normal name)", input: "kavyansh0102", expected_flagged: false, category: "False Positive Immunity" },
    ];

    let mut passed = 0;
    let total = dynamic_cases.len();
    let start_time = Instant::now();

    for case in &dynamic_cases {
        let actual = gatekeeper.is_flagged(case.input);
        assert_eq!(
            actual, case.expected_flagged,
            "FAILED: Test '{}' with input '{}'",
            case.name, case.input
        );
        passed += 1;
    }

    let elapsed = start_time.elapsed();
    println!("DYNAMIC RESULTS: {}/{} tests passed in {:.2?}", passed, total, elapsed);
}

fn create_synthetic_png(width: u32, height: u32, pattern_variant: u8) -> Vec<u8> {
    let mut img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(width, height);

    for (x, y, pixel) in img.enumerate_pixels_mut() {
        let col = (x * 8 / width) as i32;
        let row = (y * 8 / height) as i32;

        match pattern_variant {
            0 => {
                let is_bright = (col + row) % 2 == 0;
                let v = if is_bright { 230 } else { 25 };
                *pixel = Rgb([v, v, v]);
            }
            1 => {
                let is_bright = (col + row) % 2 != 0;
                let v = if is_bright { 230 } else { 25 };
                *pixel = Rgb([v, v, v]);
            }
            _ => {
                *pixel = Rgb([128, 128, 128]);
            }
        }
    }

    let mut buffer = Cursor::new(Vec::new());
    img.write_to(&mut buffer, image::ImageFormat::Png)
        .expect("Synthetic PNG encode failed");
    buffer.into_inner()
}

#[test]
fn test_pfp_sha256_cryptographic_integrity() {
    let image_a = create_synthetic_png(64, 64, 0);
    let image_b = create_synthetic_png(64, 64, 0);
    let image_c = create_synthetic_png(64, 64, 1);

    let hash_a = CryptoEngine::sha256(&image_a);
    let hash_b = CryptoEngine::sha256(&image_b);
    let hash_c = CryptoEngine::sha256(&image_c);

    assert_eq!(hash_a, hash_b, "Identical avatars must produce identical SHA-256 hashes");
    assert_ne!(hash_a, hash_c, "Different avatars must never collide");
    assert_eq!(hash_a.len(), 64, "SHA-256 string must be exactly 64 hex characters");
}

#[test]
fn test_pfp_perceptual_dhash_invariance() {
    let base_avatar = create_synthetic_png(64, 64, 0);
    let scaled_avatar = create_synthetic_png(128, 128, 0);
    let different_avatar = create_synthetic_png(64, 64, 1);

    let dhash_base = CryptoEngine::compute_dhash(&base_avatar).expect("dHash calculation failed");
    let dhash_scaled = CryptoEngine::compute_dhash(&scaled_avatar).expect("dHash calculation failed");
    let dhash_different = CryptoEngine::compute_dhash(&different_avatar).expect("dHash calculation failed");

    let distance_same_image = CryptoEngine::hamming_distance(dhash_base, dhash_scaled);
    let distance_different_image = CryptoEngine::hamming_distance(dhash_base, dhash_different);

    assert!(distance_same_image <= 5, "Perceptual dHash must recognize resized avatars as identical");
    assert!(distance_different_image > 15, "Perceptual dHash must distinguish distinct avatars");
}

#[test]
fn test_corrupt_avatar_stream_graceful_handling() {
    let garbage_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x12, 0x34];
    let empty_bytes = vec![];

    let result_garbage = CryptoEngine::compute_dhash(&garbage_bytes);
    let result_empty = CryptoEngine::compute_dhash(&empty_bytes);

    assert!(result_garbage.is_err(), "Corrupt avatar bytes must return Err, not panic");
    assert!(result_empty.is_err(), "Empty avatar bytes must return Err, not panic");
}
