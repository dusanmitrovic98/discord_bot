//! # Canvas Profile & Uncapped Leveling Test Battery

use aegis_bastion::canvas::{CanvasCompositor, CanvasScene};
use aegis_bastion::pipeline::leveling::XpWriteBackBuffer;

#[test]
fn test_canvas_profile_render_png_dimensions() {
    let scene = CanvasScene::default_classic();
    let png_bytes = CanvasCompositor::render_scene(
        &scene, "bk2o198", "Europe", "Serbia", "28", 41, 168_100, 168_100, None,
    );

    assert!(!png_bytes.is_empty());
    let img = image::load_from_memory(&png_bytes).expect("Canvas PNG must be valid");
    assert_eq!(img.width(), 800);
    assert_eq!(img.height(), 400);
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
