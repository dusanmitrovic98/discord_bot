//! # Canvas Profile & Uncapped Leveling Test Battery

use aegis_bastion::canvas::{CanvasCompositor, ProfileCardPayload};
use aegis_bastion::pipeline::leveling::XpWriteBackBuffer;

#[test]
fn test_canvas_profile_render_png_dimensions() {
    let payload = ProfileCardPayload {
        username: "bk2o198",
        continent: "Europe",
        country: "Serbia",
        age_display: "27",
        level: 41,
        xp: 168_100,
        points: 168_100,
        avatar_bytes: None,
        preset: "classic",
        theme: "crimson",
    };

    let png_bytes = CanvasCompositor::render_profile_card(payload);

    assert!(!png_bytes.is_empty());
    let img = image::load_from_memory(&png_bytes).expect("Canvas PNG must be valid");
    assert_eq!(img.width(), 800);
    assert_eq!(img.height(), 400);
}

#[test]
fn test_dota_presets_render_successfully() {
    for preset in &["classic", "showcase", "compact"] {
        let payload = ProfileCardPayload {
            username: "Dule",
            continent: "Europe",
            country: "Serbia",
            age_display: "50+",
            level: 50,
            xp: 250_100,
            points: 250_100,
            avatar_bytes: None,
            preset,
            theme: "emerald",
        };

        let png = CanvasCompositor::render_profile_card(payload);
        assert!(!png.is_empty());
    }
}

#[test]
fn test_uncapped_leveling_formula() {
    let lvl_100_xp = XpWriteBackBuffer::xp_for_level(100);
    let lvl_200_xp = XpWriteBackBuffer::xp_for_level(200);
    let lvl_500_xp = XpWriteBackBuffer::xp_for_level(500);

    assert_eq!(XpWriteBackBuffer::level_for_xp(lvl_100_xp), 100);
    assert_eq!(XpWriteBackBuffer::level_for_xp(lvl_200_xp), 200);
    assert_eq!(XpWriteBackBuffer::level_for_xp(lvl_500_xp), 500);
    assert!(lvl_500_xp > lvl_200_xp);
}
