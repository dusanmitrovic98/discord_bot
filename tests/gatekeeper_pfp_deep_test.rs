use aegis_bastion::crypto::CryptoEngine;
use aegis_bastion::gatekeeper::TextGatekeeper;
use image::{ImageBuffer, Rgb};
use std::io::Cursor;
use std::time::Instant;

// =========================================================================
// 1. EXTENSIVE USERNAME & NICKNAME ADVERSARIAL TEST BATTERY
// =========================================================================

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
        // --- CATEGORY 1: Exact Raid Accounts Reported by Architect ---
        TestCase {
            name: "Raid Acc 1",
            input: "megalink08225",
            expected_flagged: true,
            category: "Raid Exact",
        },
        TestCase {
            name: "Raid Acc 2",
            input: "cpstuuf",
            expected_flagged: true,
            category: "Raid Exact",
        },
        TestCase {
            name: "Raid Acc 3",
            input: "megalink08816",
            expected_flagged: true,
            category: "Raid Exact",
        },
        TestCase {
            name: "Raid Acc 4",
            input: "megalink0588",
            expected_flagged: true,
            category: "Raid Exact",
        },
        TestCase {
            name: "Raid Acc 5",
            input: "cpstuff08143",
            expected_flagged: true,
            category: "Raid Exact",
        },
        TestCase {
            name: "Raid Acc 6",
            input: "megalinkstuff0680",
            expected_flagged: true,
            category: "Raid Exact",
        },
        // --- CATEGORY 2: Vowel & Consonant Stretching Evasions ---
        TestCase {
            name: "Vowel stretch 1",
            input: "cpstuuuuf",
            expected_flagged: true,
            category: "Stretching",
        },
        TestCase {
            name: "Vowel stretch 2",
            input: "cpstuuuuuuuffff",
            expected_flagged: true,
            category: "Stretching",
        },
        TestCase {
            name: "Consonant stretch 1",
            input: "c.p. sttufff",
            expected_flagged: true,
            category: "Stretching",
        },
        TestCase {
            name: "Word stretch",
            input: "mmmeeegggaaallliinnkk",
            expected_flagged: true,
            category: "Stretching",
        },
        TestCase {
            name: "Single f variation",
            input: "cpstuf",
            expected_flagged: true,
            category: "Stretching",
        },
        // --- CATEGORY 3: Delimiter Padding & Intra-Character Noise ---
        TestCase {
            name: "Hyphen padded",
            input: "M-E-G-A---L-I-N-K",
            expected_flagged: true,
            category: "Delimiters",
        },
        TestCase {
            name: "Underscore padded",
            input: "m_e_g_a_l_i_n_k",
            expected_flagged: true,
            category: "Delimiters",
        },
        TestCase {
            name: "Dot padded",
            input: "c.p...s.t.u.f.f",
            expected_flagged: true,
            category: "Delimiters",
        },
        TestCase {
            name: "Mixed separators",
            input: "c-p._.stuff",
            expected_flagged: true,
            category: "Delimiters",
        },
        TestCase {
            name: "Tilde & spaces",
            input: "c ~ p ~ stuff",
            expected_flagged: true,
            category: "Delimiters",
        },
        // --- CATEGORY 4: Invisible & Zero-Width Unicode Exploits ---
        TestCase {
            name: "Zero-width space",
            input: "m\u{200B}e\u{200B}g\u{200B}a\u{200B}l\u{200B}i\u{200B}n\u{200B}k",
            expected_flagged: true,
            category: "Invisible Chars",
        },
        TestCase {
            name: "Zero-width joiner",
            input: "c\u{200D}p\u{200D}s\u{200D}t\u{200D}u\u{200D}f\u{200D}f",
            expected_flagged: true,
            category: "Invisible Chars",
        },
        TestCase {
            name: "Byte-order mark",
            input: "\u{FEFF}cpstuff\u{FEFF}",
            expected_flagged: true,
            category: "Invisible Chars",
        },
        // --- CATEGORY 5: Visual Homoglyphs (Cyrillic & Greek Lookalikes) ---
        TestCase {
            name: "Cyrillic Es and Er",
            input: "СР stuff",
            expected_flagged: true,
            category: "Homoglyphs",
        }, // 'С' (U+0421) and 'Р' (U+0420)
        TestCase {
            name: "Mixed Cyrillic text",
            input: "СР ѕтυff",
            expected_flagged: true,
            category: "Homoglyphs",
        },
        TestCase {
            name: "Full-width Japanese/Unicode",
            input: "ｍｅｇａ ｌｉｎｋ",
            expected_flagged: true,
            category: "Homoglyphs",
        },
        TestCase {
            name: "Cyrillic 'a' and 'o'",
            input: "megаlink",
            expected_flagged: true,
            category: "Homoglyphs",
        }, // 'а' is Cyrillic U+0430
        // --- CATEGORY 6: Leetspeak & Digit Injections ---
        TestCase {
            name: "Standard 1337",
            input: "m3g4 l1nk",
            expected_flagged: true,
            category: "Leetspeak",
        },
        TestCase {
            name: "Zero for O",
            input: "megalink08225",
            expected_flagged: true,
            category: "Leetspeak",
        },
        TestCase {
            name: "Dollar and At",
            input: "cp_@_stuff",
            expected_flagged: true,
            category: "Leetspeak",
        },
        TestCase {
            name: "Numeric suffix",
            input: "cpstuff9999",
            expected_flagged: true,
            category: "Leetspeak",
        },
        TestCase {
            name: "Alphanumeric mix",
            input: "M3G4_L1NK_STUFF",
            expected_flagged: true,
            category: "Leetspeak",
        },
        // --- CATEGORY 7: FALSE POSITIVE IMMUNITY TEST (Innocent Gamer Names) ---
        // MUST NEVER BE FLAGGED! Normal members must be 100% safe.
        TestCase {
            name: "Normal gamer",
            input: "normal_gamer_guy",
            expected_flagged: false,
            category: "Benign Immunity",
        },
        TestCase {
            name: "Quokka benign",
            input: "bubbly_quokka_34489",
            expected_flagged: false,
            category: "Benign Immunity",
        },
        TestCase {
            name: "Peacock (has 'p', 'c')",
            input: "stylish_peacock_82532",
            expected_flagged: false,
            category: "Benign Immunity",
        },
        TestCase {
            name: "James Access",
            input: "jamesaccess0570",
            expected_flagged: false,
            category: "Benign Immunity",
        },
        TestCase {
            name: "Contains 'recipe'",
            input: "chef_secret_recipe",
            expected_flagged: false,
            category: "Benign Immunity",
        },
        TestCase {
            name: "Contains 'captain'",
            input: "captain_america_2026",
            expected_flagged: false,
            category: "Benign Immunity",
        },
        TestCase {
            name: "Contains 'escape'",
            input: "escape_from_tarkov",
            expected_flagged: false,
            category: "Benign Immunity",
        },
        TestCase {
            name: "Contains 'description'",
            input: "job_description_hr",
            expected_flagged: false,
            category: "Benign Immunity",
        },
        TestCase {
            name: "Contains 'mega_man'",
            input: "mega_man_classic_fan",
            expected_flagged: false,
            category: "Benign Immunity",
        },
        TestCase {
            name: "Permuted letters",
            input: "cstuffp",
            expected_flagged: false,
            category: "Benign Immunity",
        },
        TestCase {
            name: "Benign space pirate",
            input: "space_pirate_captain",
            expected_flagged: false,
            category: "Benign Immunity",
        },
    ];

    println!("\n===============================================================================");
    println!("🧪 RUNNING EXTENSIVE GATEKEEPER NICKNAME/USERNAME TEST BATTERY");
    println!("===============================================================================");
    println!(
        "{:<22} | {:<25} | {:<10} | {:<8} | {:<8}",
        "Category", "Input", "Expected", "Actual", "Status"
    );
    println!("-------------------------------------------------------------------------------");

    let mut passed = 0;
    let total = cases.len();
    let start_time = Instant::now();

    for case in &cases {
        let actual = gatekeeper.is_flagged(case.input);
        let status = if actual == case.expected_flagged {
            "PASS ✅"
        } else {
            "FAIL ❌"
        };
        if actual == case.expected_flagged {
            passed += 1;
        }

        println!(
            "{:<22} | {:<25} | {:<10} | {:<8} | {}",
            case.category,
            if case.input.len() > 25 {
                &case.input[..25]
            } else {
                case.input
            },
            if case.expected_flagged {
                "FLAG"
            } else {
                "PASS"
            },
            if actual { "FLAG" } else { "PASS" },
            status
        );
        assert_eq!(
            actual, case.expected_flagged,
            "FAILED: Test '{}' with input '{}' did not match expected verdict.",
            case.name, case.input
        );
    }

    let elapsed = start_time.elapsed();
    println!("-------------------------------------------------------------------------------");
    println!(
        "🎯 RESULTS: {}/{} tests passed in {:.2?} (Average: {:.2?} per name)",
        passed,
        total,
        elapsed,
        elapsed / total as u32
    );
    println!("===============================================================================\n");
}

// =========================================================================
// 2. PROFILE PICTURE (PFP) HASHING & IMAGE PIPELINE TEST BATTERY
// =========================================================================

/// Generates a synthetic test image in-memory encoded as PNG bytes with rich spatial contrast
fn create_synthetic_png(width: u32, height: u32, pattern_variant: u8) -> Vec<u8> {
    let mut img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(width, height);

    for (x, y, pixel) in img.enumerate_pixels_mut() {
        // Normalize coordinates relative to image resolution (0 to 7 grid)
        let col = (x * 8 / width) as i32;
        let row = (y * 8 / height) as i32;

        match pattern_variant {
            0 => {
                // High-contrast alternating checkerboard
                let is_bright = (col + row) % 2 == 0;
                let v = if is_bright { 230 } else { 25 };
                *pixel = Rgb([v, v, v]);
            }
            1 => {
                // Inverted phase pattern (Completely distinct spatial frequency)
                let is_bright = (col + row) % 2 != 0;
                let v = if is_bright { 230 } else { 25 };
                *pixel = Rgb([v, v, v]);
            }
            2 => {
                // Vertical gradient
                let v = (x * 255 / width) as u8;
                *pixel = Rgb([v, 128, 255 - v]);
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
    println!("\n===============================================================================");
    println!("🧪 TESTING PROFILE PICTURE SHA-256 CRYPTOGRAPHIC INTEGRITY");
    println!("===============================================================================");

    let image_a = create_synthetic_png(64, 64, 0);
    let image_b = create_synthetic_png(64, 64, 0); // Exact clone of A
    let image_c = create_synthetic_png(64, 64, 1); // Different image

    let hash_a = CryptoEngine::sha256(&image_a);
    let hash_b = CryptoEngine::sha256(&image_b);
    let hash_c = CryptoEngine::sha256(&image_c);

    println!("Image A SHA-256: {}", hash_a);
    println!("Image B SHA-256: {}", hash_b);
    println!("Image C SHA-256: {}", hash_c);

    // Identical image streams must yield 100% identical hashes (Cache guarantee)
    assert_eq!(
        hash_a, hash_b,
        "Identical avatars must produce identical SHA-256 hashes"
    );
    // Different image streams must yield distinct hashes
    assert_ne!(hash_a, hash_c, "Different avatars must never collide");
    assert_eq!(
        hash_a.len(),
        64,
        "SHA-256 hex string must be exactly 64 characters"
    );
    println!("✅ SHA-256 Cache Invariant Verified!\n");
}

#[test]
fn test_pfp_perceptual_dhash_invariance() {
    println!("\n===============================================================================");
    println!("🧪 TESTING PFP PERCEPTUAL DIFFERENCE HASH (dHash) INVARIANCE");
    println!("===============================================================================");

    // Generate base image (pattern 0: 64x64 gradient)
    let base_avatar = create_synthetic_png(64, 64, 0);
    // Generate scaled version of same base pattern (128x128 gradient - mimics Discord resizing PFP)
    let scaled_avatar = create_synthetic_png(128, 128, 0);
    // Generate an entirely different avatar (pattern 1: horizontal stripes)
    let different_avatar = create_synthetic_png(64, 64, 1);

    let dhash_base = CryptoEngine::compute_dhash(&base_avatar).expect("dHash calculation failed");
    let dhash_scaled =
        CryptoEngine::compute_dhash(&scaled_avatar).expect("dHash calculation failed");
    let dhash_different =
        CryptoEngine::compute_dhash(&different_avatar).expect("dHash calculation failed");

    let distance_same_image = CryptoEngine::hamming_distance(dhash_base, dhash_scaled);
    let distance_different_image = CryptoEngine::hamming_distance(dhash_base, dhash_different);

    println!("dHash Base (64x64):       {:016x}", dhash_base);
    println!("dHash Scaled (128x128):   {:016x}", dhash_scaled);
    println!("dHash Different (Stripes): {:016x}", dhash_different);
    println!(
        "Hamming distance (Same image resized):   {} (Threshold: <= 5)",
        distance_same_image
    );
    println!(
        "Hamming distance (Different image):      {} (Threshold: > 15)",
        distance_different_image
    );

    // Resizing/scaling the same avatar should result in near-zero Hamming distance
    assert!(
        distance_same_image <= 5,
        "Perceptual dHash must recognize resized avatars as identical (distance: {})",
        distance_same_image
    );

    // A completely different avatar must yield a significant perceptual distance
    assert!(
        distance_different_image > 15,
        "Perceptual dHash must distinguish distinct avatars (distance: {})",
        distance_different_image
    );

    println!("✅ Perceptual Hashing Robustness Verified!\n");
}

#[test]
fn test_corrupt_avatar_stream_graceful_handling() {
    println!("\n===============================================================================");
    println!("🧪 TESTING TRUNCATED & CORRUPT AVATAR STREAMS (NASA Fault-Tolerance)");
    println!("===============================================================================");

    // Malicious or broken byte stream (e.g. truncated download or garbage attack)
    let garbage_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x12, 0x34];
    let empty_bytes = vec![];

    let result_garbage = CryptoEngine::compute_dhash(&garbage_bytes);
    let result_empty = CryptoEngine::compute_dhash(&empty_bytes);

    // The system must return structured Err(AegisError::CryptoError) and NEVER panic
    assert!(
        result_garbage.is_err(),
        "Corrupt avatar bytes must return Err, not panic"
    );
    assert!(
        result_empty.is_err(),
        "Empty avatar bytes must return Err, not panic"
    );

    println!(
        "Corrupt stream error caught cleanly: {:?}",
        result_garbage.err().unwrap()
    );
    println!(
        "Empty stream error caught cleanly:   {:?}",
        result_empty.err().unwrap()
    );
    println!("✅ NASA Non-Panicking Invariant Verified!\n");
}
