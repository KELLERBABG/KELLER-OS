//! 2D rasteriser for the display server: flat rectangles, borders, lines and text
//! (GUI_SPECIFICATION.md §5 phase 2).
//!
//! Everything draws into a [`Canvas`]: a packed `u32` backbuffer owned by the display
//! server, never the framebuffer itself, so a repaint is never visible half-finished. The
//! only font is the baked 8x16 table, so text costs no allocations and no font engine.

use super::font::{FONT_8X16, GLYPH_BYTES, GLYPH_HEIGHT, GLYPH_WIDTH};
use alloc::vec::Vec;

/// Text cell geometry, used by every caller that lays text out.
pub const CHAR_WIDTH: u32 = GLYPH_WIDTH as u32;
pub const CHAR_HEIGHT: u32 = GLYPH_HEIGHT as u32;

/// Palette from GUI_SPECIFICATION.md §5: flat, high contrast, dark by default.
pub const BG: u32 = 0x0003_0712;
pub const PANEL: u32 = 0x000F_172A;
pub const BORDER: u32 = 0x0063_66F1;
pub const TEXT: u32 = 0x00F8_FAFC;
pub const TEXT_DIM: u32 = 0x0094_A3B8;
pub const DANGER: u32 = 0x00EF_4444;
pub const SECURE: u32 = 0x0010_B981;
/// Title-bar strip, a shade above the panel colour.
pub const CHROME: u32 = 0x001B_2438;

/// Packs a color the way the framebuffer expects it (`0x00RRGGBB`).
pub const fn rgb(red: u32, green: u32, blue: u32) -> u32 {
    ((red & 0xFF) << 16) | ((green & 0xFF) << 8) | (blue & 0xFF)
}

/// A pixel rectangle. Rectangles are the only geometry the display server speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub const fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub fn right(&self) -> u32 {
        self.x + self.width
    }

    pub fn bottom(&self) -> u32 {
        self.y + self.height
    }

    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// Bounding box of two rectangles (used to merge dirty regions).
    pub fn union(&self, other: &Rect) -> Rect {
        let x = core::cmp::min(self.x, other.x);
        let y = core::cmp::min(self.y, other.y);
        let right = core::cmp::max(self.right(), other.right());
        let bottom = core::cmp::max(self.bottom(), other.bottom());
        Rect::new(x, y, right - x, bottom - y)
    }

    pub fn intersects(&self, other: &Rect) -> bool {
        self.x < other.right()
            && other.x < self.right()
            && self.y < other.bottom()
            && other.y < self.bottom()
    }

    /// Overlap of two rectangles (empty when they are disjoint).
    ///
    /// The repaint pass draws the whole scene clipped to each rectangle that needs pixels, so
    /// every draw call intersects its own panel with the caller's rectangle first.
    pub fn intersect(&self, other: &Rect) -> Rect {
        let x = core::cmp::max(self.x, other.x);
        let y = core::cmp::max(self.y, other.y);
        let right = core::cmp::min(self.right(), other.right());
        let bottom = core::cmp::min(self.bottom(), other.bottom());
        if right <= x || bottom <= y {
            Rect::new(x, y, 0, 0)
        } else {
            Rect::new(x, y, right - x, bottom - y)
        }
    }

    /// Hit test, used to decide which window a click grants focus to.
    pub fn contains(&self, x: u32, y: u32) -> bool {
        x >= self.x && x < self.right() && y >= self.y && y < self.bottom()
    }
}

/// A packed backbuffer with drawing primitives and optional clipping.
pub struct Canvas {
    pixels: Vec<u32>,
    width: u32,
    height: u32,
    clip: Rect,
    fills: u64,
    glyphs: u64,
}

impl Canvas {
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            pixels: alloc::vec![BG; (width as usize) * (height as usize)],
            width,
            height,
            clip: Rect::new(0, 0, width, height),
            fills: 0,
            glyphs: 0,
        }
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn pixels(&self) -> &[u32] {
        &self.pixels
    }

    pub fn pixels_mut(&mut self) -> &mut [u32] {
        &mut self.pixels
    }

    pub fn bytes(&self) -> u64 {
        (self.pixels.len() * 4) as u64
    }

    pub fn fill_count(&self) -> u64 {
        self.fills
    }

    pub fn glyph_count(&self) -> u64 {
        self.glyphs
    }

    /// Restricts drawing to a rectangle (the backbuffer's own bounds always apply).
    pub fn set_clip(&mut self, rect: Rect) {
        self.clip = rect;
    }

    pub fn reset_clip(&mut self) {
        self.clip = Rect::new(0, 0, self.width, self.height);
    }

    pub fn clear(&mut self, color: u32) {
        for pixel in self.pixels.iter_mut() {
            *pixel = color & 0x00FF_FFFF;
        }
    }

    pub fn put_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.clip.x
            && x < self.clip.right()
            && y >= self.clip.y
            && y < self.clip.bottom()
            && x < self.width
            && y < self.height
        {
            self.pixels[(y as usize) * (self.width as usize) + x as usize] = color & 0x00FF_FFFF;
        }
    }

    pub fn get_pixel(&self, x: u32, y: u32) -> Option<u32> {
        if x < self.width && y < self.height {
            Some(self.pixels[(y as usize) * (self.width as usize) + x as usize])
        } else {
            None
        }
    }

    pub fn fill_rect(&mut self, rect: Rect, color: u32) {
        let color = color & 0x00FF_FFFF;
        let x0 = core::cmp::max(rect.x, self.clip.x);
        let y0 = core::cmp::max(rect.y, self.clip.y);
        let x1 = core::cmp::min(rect.right(), core::cmp::min(self.clip.right(), self.width));
        let y1 = core::cmp::min(rect.bottom(), core::cmp::min(self.clip.bottom(), self.height));
        if x0 >= x1 || y0 >= y1 {
            return;
        }
        self.fills += 1;
        for y in y0..y1 {
            let start = (y as usize) * (self.width as usize) + x0 as usize;
            let end = (y as usize) * (self.width as usize) + x1 as usize;
            for pixel in self.pixels[start..end].iter_mut() {
                *pixel = color;
            }
        }
    }

    /// One-pixel outline. Kept as four fills so overlapping rectangles cannot double-brighten.
    pub fn draw_rect_border(&mut self, rect: Rect, color: u32) {
        if rect.is_empty() {
            return;
        }
        self.fill_rect(Rect::new(rect.x, rect.y, rect.width, 1), color);
        self.fill_rect(
            Rect::new(rect.x, rect.bottom().saturating_sub(1), rect.width, 1),
            color,
        );
        self.fill_rect(Rect::new(rect.x, rect.y, 1, rect.height), color);
        self.fill_rect(
            Rect::new(rect.right().saturating_sub(1), rect.y, 1, rect.height),
            color,
        );
    }

    pub fn draw_hline(&mut self, x: u32, y: u32, width: u32, color: u32) {
        self.fill_rect(Rect::new(x, y, width, 1), color);
    }

    pub fn draw_vline(&mut self, x: u32, y: u32, height: u32, color: u32) {
        self.fill_rect(Rect::new(x, y, 1, height), color);
    }

    /// Bresenham line; used for the crosshair and separators.
    pub fn draw_line(&mut self, mut x0: i64, mut y0: i64, x1: i64, y1: i64, color: u32) {
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut error = dx + dy;
        loop {
            if x0 >= 0 && y0 >= 0 {
                self.put_pixel(x0 as u32, y0 as u32, color);
            }
            if x0 == x1 && y0 == y1 {
                break;
            }
            let doubled = 2 * error;
            if doubled >= dy {
                error += dy;
                x0 += sx;
            }
            if doubled <= dx {
                error += dx;
                y0 += sy;
            }
        }
    }

    /// Draws one glyph. `background` is optional so text can sit on a filled strip.
    pub fn draw_char(&mut self, x: u32, y: u32, byte: u8, foreground: u32, background: Option<u32>) {
        let glyph = (byte as usize) * GLYPH_BYTES;
        if glyph + GLYPH_BYTES > FONT_8X16.len() {
            return;
        }
        self.glyphs += 1;
        for row in 0..GLYPH_HEIGHT {
            let bits = FONT_8X16[glyph + row];
            for column in 0..GLYPH_WIDTH {
                let lit = bits & (0x80 >> column) != 0;
                let color = if lit {
                    foreground
                } else {
                    match background {
                        Some(color) => color,
                        None => continue,
                    }
                };
                self.put_pixel(x + column as u32, y + row as u32, color);
            }
        }
    }

    /// Draws a string and returns the x coordinate after the last glyph.
    pub fn draw_string(
        &mut self,
        x: u32,
        y: u32,
        text: &str,
        foreground: u32,
        background: Option<u32>,
    ) -> u32 {
        let mut cursor = x;
        for byte in text.bytes() {
            if byte == b'\n' || byte == b'\r' {
                continue;
            }
            self.draw_char(cursor, y, byte, foreground, background);
            cursor += CHAR_WIDTH;
        }
        cursor
    }

    /// Draws at most `columns` characters (tile text never spills past its panel).
    pub fn draw_string_clipped(
        &mut self,
        x: u32,
        y: u32,
        text: &str,
        foreground: u32,
        background: Option<u32>,
        columns: u32,
    ) {
        let mut cursor = x;
        let mut drawn = 0u32;
        for byte in text.bytes() {
            if drawn >= columns {
                break;
            }
            if byte == b'\n' || byte == b'\r' {
                continue;
            }
            self.draw_char(cursor, y, byte, foreground, background);
            cursor += CHAR_WIDTH;
            drawn += 1;
        }
    }
}
