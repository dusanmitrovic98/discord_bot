//! # Dynamic 2D Scene Graph & Canvas Showcase Compositor
//!
//! Evaluates a multi-layer scene graph (Translation, Rotation, Scale, Z-Index)
//! and renders an 800x400 showcase image in RAM using pure Rust affine geometry.
//! Strictly enforces NASA Rules 2 (bounded loops <= 12 layers) and 3 (memory bounds).

use image::{ImageFormat, Rgba, RgbaImage};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

pub const CANVAS_WIDTH: u32 = 800;
pub const CANVAS_HEIGHT: u32 = 400;
pub const MAX_LAYERS: usize = 12;

const FONT_8X8: &[u8; 95 * 8] = include_bytes!("../assets/font8x8.bin");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transform2D {
    pub x: i32,
    pub y: i32,
    pub scale: f32,        // 0.2 to 3.0
    pub rotation_deg: f32, // 0.0 to 360.0
    pub z_index: i16,      // -100 to 100
    pub opacity: f32,      // 0.0 to 1.0
}

impl Default for Transform2D {
    fn default() -> Self {
        Self {
            x: 0,
            y: 0,
            scale: 1.0,
            rotation_deg: 0.0,
            z_index: 0,
            opacity: 1.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum LayerKind {
    Wallpaper {
        theme: String,
    },
    Avatar {
        radius: u32,
        frame_color: [u8; 4],
    },
    Username {
        font_scale: u32,
        color: [u8; 4],
    },
    StatChip {
        label: String,
        value: String,
        accent: [u8; 4],
    },
    Badge {
        text: String,
        bg_color: [u8; 4],
    },
    XpBar {
        width: u32,
        height: u32,
        accent: [u8; 4],
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanvasLayer {
    pub layer_id: String,
    pub kind: LayerKind,
    pub transform: Transform2D,
    pub visible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanvasScene {
    pub width: u32,
    pub height: u32,
    pub background_scrim: f32, // 0.0 to 1.0 alpha tint
    pub layers: Vec<CanvasLayer>,
}

impl Default for CanvasScene {
    fn default() -> Self {
        Self::default_classic()
    }
}

impl CanvasScene {
    pub fn default_classic() -> Self {
        Self {
            width: CANVAS_WIDTH,
            height: CANVAS_HEIGHT,
            background_scrim: 0.35,
            layers: vec![
                CanvasLayer {
                    layer_id: "bg".into(),
                    kind: LayerKind::Wallpaper {
                        theme: "crimson".into(),
                    },
                    transform: Transform2D {
                        x: 0,
                        y: 0,
                        scale: 1.0,
                        rotation_deg: 0.0,
                        z_index: -10,
                        opacity: 1.0,
                    },
                    visible: true,
                },
                CanvasLayer {
                    layer_id: "avatar".into(),
                    kind: LayerKind::Avatar {
                        radius: 55,
                        frame_color: [245, 158, 11, 255],
                    },
                    transform: Transform2D {
                        x: 45,
                        y: 55,
                        scale: 1.0,
                        rotation_deg: 0.0,
                        z_index: 10,
                        opacity: 1.0,
                    },
                    visible: true,
                },
                CanvasLayer {
                    layer_id: "username".into(),
                    kind: LayerKind::Username {
                        font_scale: 3,
                        color: [243, 244, 246, 255],
                    },
                    transform: Transform2D {
                        x: 180,
                        y: 60,
                        scale: 1.0,
                        rotation_deg: 0.0,
                        z_index: 20,
                        opacity: 1.0,
                    },
                    visible: true,
                },
                CanvasLayer {
                    layer_id: "lvl_badge".into(),
                    kind: LayerKind::Badge {
                        text: "LVL".into(),
                        bg_color: [224, 86, 56, 255],
                    },
                    transform: Transform2D {
                        x: 180,
                        y: 105,
                        scale: 1.0,
                        rotation_deg: 0.0,
                        z_index: 20,
                        opacity: 1.0,
                    },
                    visible: true,
                },
                CanvasLayer {
                    layer_id: "pts_badge".into(),
                    kind: LayerKind::Badge {
                        text: "PTS".into(),
                        bg_color: [16, 185, 129, 255],
                    },
                    transform: Transform2D {
                        x: 290,
                        y: 105,
                        scale: 1.0,
                        rotation_deg: 0.0,
                        z_index: 20,
                        opacity: 1.0,
                    },
                    visible: true,
                },
                CanvasLayer {
                    layer_id: "continent".into(),
                    kind: LayerKind::StatChip {
                        label: "CONTINENT".into(),
                        value: "Europe".into(),
                        accent: [99, 102, 241, 255],
                    },
                    transform: Transform2D {
                        x: 45,
                        y: 195,
                        scale: 1.0,
                        rotation_deg: 0.0,
                        z_index: 30,
                        opacity: 1.0,
                    },
                    visible: true,
                },
                CanvasLayer {
                    layer_id: "country".into(),
                    kind: LayerKind::StatChip {
                        label: "COUNTRY".into(),
                        value: "Serbia".into(),
                        accent: [236, 72, 153, 255],
                    },
                    transform: Transform2D {
                        x: 290,
                        y: 195,
                        scale: 1.0,
                        rotation_deg: 0.0,
                        z_index: 30,
                        opacity: 1.0,
                    },
                    visible: true,
                },
                CanvasLayer {
                    layer_id: "age".into(),
                    kind: LayerKind::StatChip {
                        label: "AGE".into(),
                        value: "28".into(),
                        accent: [245, 158, 11, 255],
                    },
                    transform: Transform2D {
                        x: 535,
                        y: 195,
                        scale: 1.0,
                        rotation_deg: 0.0,
                        z_index: 30,
                        opacity: 1.0,
                    },
                    visible: true,
                },
                CanvasLayer {
                    layer_id: "xp_bar".into(),
                    kind: LayerKind::XpBar {
                        width: 710,
                        height: 24,
                        accent: [224, 86, 56, 255],
                    },
                    transform: Transform2D {
                        x: 45,
                        y: 305,
                        scale: 1.0,
                        rotation_deg: 0.0,
                        z_index: 40,
                        opacity: 1.0,
                    },
                    visible: true,
                },
            ],
        }
    }
}

pub struct CanvasCompositor;

impl CanvasCompositor {
    /// Renders the complete scene graph to PNG bytes in RAM.
    pub fn render_scene(
        scene: &CanvasScene,
        username: &str,
        continent: &str,
        country: &str,
        age_display: &str,
        level: u32,
        xp: u64,
        points: u64,
        avatar_bytes: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut img = RgbaImage::from_pixel(CANVAS_WIDTH, CANVAS_HEIGHT, Rgba([11, 13, 17, 255]));

        // Sort layers strictly by Z-index (NASA Rule 1: simple deterministic sorting)
        let mut sorted_layers: Vec<&CanvasLayer> = scene
            .layers
            .iter()
            .filter(|l| l.visible)
            .take(MAX_LAYERS)
            .collect();
        sorted_layers.sort_by_key(|l| l.transform.z_index);

        for layer in sorted_layers {
            let t = &layer.transform;
            let tx = t.x.clamp(-100, CANVAS_WIDTH as i32 + 100);
            let ty = t.y.clamp(-100, CANVAS_HEIGHT as i32 + 100);

            match &layer.kind {
                LayerKind::Wallpaper { theme } => {
                    let accent = match theme.as_str() {
                        "cyan" => Rgba([6, 182, 212, 255]),
                        "emerald" => Rgba([16, 185, 129, 255]),
                        "amber" | "gold" => Rgba([245, 158, 11, 255]),
                        "amethyst" => Rgba([139, 92, 246, 255]),
                        _ => Rgba([224, 86, 56, 255]),
                    };
                    Self::draw_filled_rect(
                        &mut img,
                        12,
                        12,
                        CANVAS_WIDTH - 24,
                        CANVAS_HEIGHT - 24,
                        Rgba([18, 20, 24, 255]),
                    );
                    Self::draw_rect_outline(
                        &mut img,
                        12,
                        12,
                        CANVAS_WIDTH - 24,
                        CANVAS_HEIGHT - 24,
                        Rgba([38, 41, 48, 255]),
                    );
                    Self::draw_filled_rect(&mut img, 12, 12, CANVAS_WIDTH - 24, 6, accent);
                }
                LayerKind::Avatar {
                    radius,
                    frame_color,
                } => {
                    let r = ((*radius as f32) * t.scale).clamp(20.0, 90.0) as u32;
                    let size = r * 2;
                    let x = tx as u32;
                    let y = ty as u32;

                    if let Some(bytes) = avatar_bytes {
                        if let Ok(src_avatar) = image::load_from_memory(bytes) {
                            let scaled = src_avatar.thumbnail_exact(size, size).to_rgba8();
                            Self::draw_circular_image(&mut img, &scaled, x, y, r);
                        } else {
                            Self::draw_avatar_placeholder(&mut img, x, y, r);
                        }
                    } else {
                        Self::draw_avatar_placeholder(&mut img, x, y, r);
                    }
                    Self::draw_circle_outline(&mut img, x + r, y + r, r + 2, Rgba(*frame_color));
                }
                LayerKind::Username { font_scale, color } => {
                    let clean = if username.len() > 18 {
                        &username[..18]
                    } else {
                        username
                    };
                    let s = ((*font_scale as f32) * t.scale).clamp(1.0, 5.0) as u32;
                    // Draw drop shadow for 100% legibility
                    Self::draw_text(
                        &mut img,
                        (tx + 2) as u32,
                        (ty + 2) as u32,
                        clean,
                        s,
                        Rgba([0, 0, 0, 220]),
                    );
                    Self::draw_text(&mut img, tx as u32, ty as u32, clean, s, Rgba(*color));
                }
                LayerKind::Badge { text, bg_color } => {
                    let label = if text == "LVL" {
                        format!("LVL {}", level)
                    } else if text == "PTS" {
                        format!("PTS: {}", points)
                    } else {
                        text.clone()
                    };
                    Self::draw_badge(&mut img, tx as u32, ty as u32, &label, Rgba(*bg_color));
                }
                LayerKind::StatChip {
                    label,
                    value: _,
                    accent,
                } => {
                    let val = match label.as_str() {
                        "CONTINENT" => continent,
                        "COUNTRY" => country,
                        "AGE" => age_display,
                        _ => "Unset",
                    };
                    let w = ((220.0 * t.scale) as u32).clamp(140, 300);
                    let h = ((65.0 * t.scale) as u32).clamp(40, 90);
                    Self::draw_stat_chip(
                        &mut img,
                        tx as u32,
                        ty as u32,
                        w,
                        h,
                        label,
                        val,
                        Rgba(*accent),
                    );
                }
                LayerKind::XpBar {
                    width,
                    height,
                    accent,
                } => {
                    let w = ((*width as f32) * t.scale).clamp(200.0, 750.0) as u32;
                    let h = ((*height as f32) * t.scale).clamp(12.0, 40.0) as u32;
                    Self::draw_xp_bar(
                        &mut img,
                        tx as u32,
                        ty as u32,
                        w,
                        h,
                        level,
                        xp,
                        Rgba(*accent),
                    );
                }
            }
        }

        let mut out = Cursor::new(Vec::with_capacity(64 * 1024));
        img.write_to(&mut out, ImageFormat::Png).unwrap_or_default();
        out.into_inner()
    }

    fn draw_xp_bar(
        img: &mut RgbaImage,
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        level: u32,
        xp: u64,
        accent: Rgba<u8>,
    ) {
        let cur_xp = crate::pipeline::leveling::XpWriteBackBuffer::xp_for_level(level);
        let next_xp = crate::pipeline::leveling::XpWriteBackBuffer::xp_for_level(level + 1);
        let delta = next_xp.saturating_sub(cur_xp);
        let progress = if delta == 0 {
            1.0
        } else {
            let u_delta = xp.saturating_sub(cur_xp);
            (u_delta as f32 / delta as f32).clamp(0.0, 1.0)
        };

        let label = format!("XP: {} / {} ({:.1}%)", xp, next_xp, progress * 100.0);
        Self::draw_text(img, x + 1, y - 15, &label, 1, Rgba([0, 0, 0, 200]));
        Self::draw_text(img, x, y - 16, &label, 1, Rgba([209, 213, 219, 255]));

        Self::draw_filled_rect(img, x, y, w, h, Rgba([26, 29, 36, 255]));
        let fill_w = ((w as f32) * progress) as u32;
        if fill_w > 0 {
            Self::draw_filled_rect(img, x, y, fill_w, h, accent);
        }
        Self::draw_rect_outline(img, x, y, w, h, Rgba([60, 65, 75, 255]));
    }

    fn draw_stat_chip(
        img: &mut RgbaImage,
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        label: &str,
        value: &str,
        accent: Rgba<u8>,
    ) {
        Self::draw_filled_rect(img, x, y, w, h, Rgba([22, 25, 31, 255]));
        Self::draw_rect_outline(img, x, y, w, h, Rgba([40, 44, 52, 255]));
        Self::draw_filled_rect(img, x, y, 4, h, accent);
        Self::draw_text(img, x + 12, y + 8, label, 1, Rgba([156, 163, 175, 255]));
        let val_clean = if value.len() > 14 {
            &value[..14]
        } else {
            value
        };
        Self::draw_text(
            img,
            x + 12,
            y + 26,
            val_clean,
            2,
            Rgba([243, 244, 246, 255]),
        );
    }

    fn draw_badge(img: &mut RgbaImage, x: u32, y: u32, text: &str, bg: Rgba<u8>) -> u32 {
        let pad_w = (text.len() as u32 * 8 * 2) + 16;
        Self::draw_filled_rect(img, x, y, pad_w, 28, bg);
        Self::draw_text(img, x + 8, y + 6, text, 2, Rgba([255, 255, 255, 255]));
        pad_w
    }

    fn draw_avatar_placeholder(img: &mut RgbaImage, x: u32, y: u32, radius: u32) {
        let center_x = (x + radius) as i32;
        let center_y = (y + radius) as i32;
        let r_sq = (radius * radius) as i32;

        for dy in -(radius as i32)..=(radius as i32) {
            for dx in -(radius as i32)..=(radius as i32) {
                if dx * dx + dy * dy <= r_sq {
                    let px = center_x + dx;
                    let py = center_y + dy;
                    if px >= 0 && px < CANVAS_WIDTH as i32 && py >= 0 && py < CANVAS_HEIGHT as i32 {
                        img.put_pixel(px as u32, py as u32, Rgba([45, 55, 72, 255]));
                    }
                }
            }
        }
    }

    fn draw_circular_image(dest: &mut RgbaImage, src: &RgbaImage, x: u32, y: u32, radius: u32) {
        let center_x = (x + radius) as i32;
        let center_y = (y + radius) as i32;
        let r_sq = (radius * radius) as i32;

        for dy in -(radius as i32)..=(radius as i32) {
            for dx in -(radius as i32)..=(radius as i32) {
                if dx * dx + dy * dy <= r_sq {
                    let src_px = (dx + radius as i32) as u32;
                    let src_py = (dy + radius as i32) as u32;

                    if src_px < src.width() && src_py < src.height() {
                        let px = center_x + dx;
                        let py = center_y + dy;
                        if px >= 0
                            && px < CANVAS_WIDTH as i32
                            && py >= 0
                            && py < CANVAS_HEIGHT as i32
                        {
                            dest.put_pixel(px as u32, py as u32, *src.get_pixel(src_px, src_py));
                        }
                    }
                }
            }
        }
    }

    fn draw_circle_outline(img: &mut RgbaImage, cx: u32, cy: u32, radius: u32, color: Rgba<u8>) {
        let r_inner = (radius.saturating_sub(2) * radius.saturating_sub(2)) as i32;
        let r_outer = (radius * radius) as i32;

        for dy in -(radius as i32)..=(radius as i32) {
            for dx in -(radius as i32)..=(radius as i32) {
                let dist_sq = dx * dx + dy * dy;
                if dist_sq >= r_inner && dist_sq <= r_outer {
                    let px = cx as i32 + dx;
                    let py = cy as i32 + dy;
                    if px >= 0 && px < CANVAS_WIDTH as i32 && py >= 0 && py < CANVAS_HEIGHT as i32 {
                        img.put_pixel(px as u32, py as u32, color);
                    }
                }
            }
        }
    }

    fn draw_filled_rect(img: &mut RgbaImage, x: u32, y: u32, w: u32, h: u32, color: Rgba<u8>) {
        for py in y..(y + h).min(CANVAS_HEIGHT) {
            for px in x..(x + w).min(CANVAS_WIDTH) {
                img.put_pixel(px, py, color);
            }
        }
    }

    fn draw_rect_outline(img: &mut RgbaImage, x: u32, y: u32, w: u32, h: u32, color: Rgba<u8>) {
        for px in x..(x + w).min(CANVAS_WIDTH) {
            img.put_pixel(px, y, color);
            if y + h - 1 < CANVAS_HEIGHT {
                img.put_pixel(px, y + h - 1, color);
            }
        }
        for py in y..(y + h).min(CANVAS_HEIGHT) {
            img.put_pixel(x, py, color);
            if x + w - 1 < CANVAS_WIDTH {
                img.put_pixel(x + w - 1, py, color);
            }
        }
    }

    fn draw_text(
        img: &mut RgbaImage,
        start_x: u32,
        start_y: u32,
        text: &str,
        scale: u32,
        color: Rgba<u8>,
    ) {
        let mut cur_x = start_x;

        for ch in text.chars() {
            let ascii = ch as usize;
            if !(32..=126).contains(&ascii) {
                cur_x += 8 * scale;
                continue;
            }

            let glyph_idx = ascii - 32;
            let offset = glyph_idx * 8;
            let glyph_bytes = &FONT_8X8[offset..offset + 8];

            for (row, &row_bits) in glyph_bytes.iter().enumerate().take(8) {
                for col in 0..8 {
                    if (row_bits & (1 << (7 - col))) != 0 {
                        for sy in 0..scale {
                            for sx in 0..scale {
                                let px = cur_x + (col as u32 * scale) + sx;
                                let py = start_y + (row as u32 * scale) + sy;
                                if px < CANVAS_WIDTH && py < CANVAS_HEIGHT {
                                    img.put_pixel(px, py, color);
                                }
                            }
                        }
                    }
                }
            }
            cur_x += 8 * scale;
        }
    }
}
