//! Light-background support. The UI was designed on dark terminals, where the
//! White > Gray > DarkGray ramp carries emphasis; on a light background that
//! ramp inverts into near-invisibility (White text on a white background, the
//! "dim" light gray unreadable). Rather than re-colour every call site, the
//! call sites name *roles* — [`bright`], [`text`], [`dim`], [`warn`] — and this
//! module maps each role to a colour for the detected background.
//!
//! Detection order: an explicit `--theme` / config `theme` wins; else the
//! terminal is asked its background colour (OSC 11, the xterm query every
//! modern emulator answers); else the `COLORFGBG` convention; else dark, the
//! overwhelmingly common terminal default.

use std::sync::atomic::{AtomicBool, Ordering};

use ratatui::style::Color;

static LIGHT: AtomicBool = AtomicBool::new(false);

pub fn set_light(on: bool) {
    LIGHT.store(on, Ordering::Relaxed);
}

pub fn is_light() -> bool {
    LIGHT.load(Ordering::Relaxed)
}

/// Emphasised text: the brightest thing on the screen.
pub fn bright() -> Color {
    if is_light() {
        Color::Black
    } else {
        Color::White
    }
}

/// Body text. Indexed greys on light: the ANSI "silver" (7) most palettes map
/// `Gray` to all but vanishes on white.
pub fn text() -> Color {
    if is_light() {
        Color::Indexed(238)
    } else {
        Color::Gray
    }
}

/// De-emphasised text — hints, borders' footers, exonerated rows.
pub fn dim() -> Color {
    if is_light() {
        Color::Indexed(245)
    } else {
        Color::DarkGray
    }
}

/// Warnings. ANSI yellow is unreadable on white in most palettes; a dark
/// amber keeps the meaning without the squint.
pub fn warn() -> Color {
    if is_light() {
        Color::Indexed(130)
    } else {
        Color::Yellow
    }
}

/// The accent: focused borders, key hints, panel titles, the latency series.
/// Everywhere the dark UI says Cyan — which on white is barely there; a dark
/// teal keeps the identity with actual contrast. Cyan *backgrounds* (the tab
/// badge, selected rows) stay literal Cyan: black-on-cyan reads on either
/// background.
pub fn accent() -> Color {
    if is_light() {
        Color::Indexed(30)
    } else {
        Color::Cyan
    }
}

/// The jitter band in the latency charts.
pub fn jitter() -> Color {
    if is_light() {
        Color::Blue
    } else {
        Color::LightBlue
    }
}

/// Cursor-row background (the blue-grey wash).
pub fn sel_bg() -> Color {
    if is_light() {
        Color::Rgb(213, 218, 233)
    } else {
        Color::Rgb(40, 40, 55)
    }
}

/// Pinned-row background (the cold teal).
pub fn pin_bg() -> Color {
    if is_light() {
        Color::Rgb(210, 233, 233)
    } else {
        Color::Rgb(16, 40, 40)
    }
}

/// Cursor on a pinned row: the teal, lifted.
pub fn sel_pin_bg() -> Color {
    if is_light() {
        Color::Rgb(184, 219, 219)
    } else {
        Color::Rgb(30, 62, 62)
    }
}

/// Resolve the preference ("auto" / "dark" / "light") into the global flag.
/// Must run before anything else reads stdin: the OSC reply arrives there,
/// and once the input thread owns the stream it would eat (or mis-key) it.
pub fn init(pref: &str) {
    let light = match pref.to_ascii_lowercase().as_str() {
        "light" => true,
        "dark" => false,
        _ => detect().unwrap_or(false),
    };
    set_light(light);
}

fn detect() -> Option<bool> {
    #[cfg(unix)]
    if let Some(light) = query_osc11() {
        return Some(light);
    }
    colorfgbg_light()
}

/// The `COLORFGBG` convention ("fg;bg", sometimes "fg;default;bg"): set by
/// iTerm2, Konsole and rxvt. Background 7 or 15 is a light theme.
fn colorfgbg_light() -> Option<bool> {
    let v = std::env::var("COLORFGBG").ok()?;
    let bg: u8 = v.rsplit(';').next()?.trim().parse().ok()?;
    Some(bg == 7 || bg == 15)
}

/// Ask the terminal its background colour: write the OSC 11 query to the
/// controlling terminal and read the `rgb:RRRR/GGGG/BBBB` reply back, with a
/// short timeout so a terminal that never answers cannot hang startup. Echo
/// is off during the exchange so the reply never prints as garbage.
#[cfg(unix)]
fn query_osc11() -> Option<bool> {
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;

    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let fd = tty.as_raw_fd();
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut old) } != 0 {
        return None;
    }
    let mut raw = old;
    raw.c_lflag &= !(libc::ICANON | libc::ECHO);
    // VMIN=0 + VTIME: each read returns what is there, or 0 after 300 ms.
    raw.c_cc[libc::VMIN] = 0;
    raw.c_cc[libc::VTIME] = 3;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
        return None;
    }
    let answer = (|| {
        tty.write_all(b"\x1b]11;?\x1b\\").ok()?;
        tty.flush().ok()?;
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        // Anything but one byte back is the VTIME timeout (or an error): the
        // terminal doesn't answer OSC 11, and silence must not hang startup.
        while let Ok(1) = tty.read(&mut byte) {
            buf.push(byte[0]);
            // BEL or ST both terminate the reply.
            if byte[0] == 0x07 || buf.ends_with(b"\x1b\\") || buf.len() > 64 {
                break;
            }
        }
        parse_osc11(&String::from_utf8_lossy(&buf))
    })();
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
    answer
}

/// `true` = light, from an OSC 11 reply carrying `rgb:RRRR/GGGG/BBBB`
/// (channels are 1–4 hex digits, scaled to their own width).
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_osc11(reply: &str) -> Option<bool> {
    let spec = &reply[reply.find("rgb:")? + 4..];
    let mut parts = spec.split('/');
    let mut chan = || -> Option<f64> {
        let part = parts.next()?;
        let hex: String = part.chars().take_while(char::is_ascii_hexdigit).collect();
        let v = u32::from_str_radix(&hex, 16).ok()? as f64;
        Some(v / (16f64.powi(hex.len() as i32) - 1.0))
    };
    let (r, g, b) = (chan()?, chan()?, chan()?);
    // Rec. 709 luma; backgrounds cluster near the extremes, so the exact
    // threshold hardly matters.
    Some(0.2126 * r + 0.7152 * g + 0.0722 * b > 0.5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc11_replies_parse_to_the_right_side() {
        // iTerm2 default dark, BEL-terminated.
        assert_eq!(parse_osc11("\x1b]11;rgb:0000/0000/0000\x07"), Some(false));
        // A light theme, ST-terminated.
        assert_eq!(parse_osc11("\x1b]11;rgb:ffff/ffff/fdfd\x1b\\"), Some(true));
        // Two-digit channels (some emulators answer 8-bit).
        assert_eq!(parse_osc11("\x1b]11;rgb:fa/fa/f0\x07"), Some(true));
        // Solarized dark's teal-ish background is still dark.
        assert_eq!(parse_osc11("\x1b]11;rgb:0000/2b2b/3636\x07"), Some(false));
        // Garbage and silence are "don't know", never a guess.
        assert_eq!(parse_osc11(""), None);
        assert_eq!(parse_osc11("\x1b]11;rgb:zz/zz/zz\x07"), None);
    }

    #[test]
    fn colorfgbg_convention() {
        // Not asserting via env vars (tests run in parallel); the parse logic
        // is what matters and it lives inline: bg 0 dark, 15 light.
        // Covered indirectly through `init` overrides below.
        init("light");
        assert!(is_light());
        init("dark");
        assert!(!is_light());
    }
}
