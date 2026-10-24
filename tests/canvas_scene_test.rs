//! # 2D Scene Graph & Compositor Unit Test Battery

use aegis_bastion::canvas::{CanvasCompositor, CanvasScene};

#[test]
fn test_default_scene_compositor_render() {
    let scene = CanvasScene::default_classic();
    let png = CanvasCompositor::render_scene(
        &scene, "Dule", "Europe", "Serbia", "28", 41, 168_100, 168_100, None,
    );

    assert!(!png.is_empty());
    let img = image::load_from_memory(&png).expect("Scene PNG must be valid");
    assert_eq!(img.width(), 800);
    assert_eq!(img.height(), 400);
}
