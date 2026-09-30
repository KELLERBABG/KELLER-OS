//! Build integrity: self-hash of the loaded `.text` section.
//!
//! `SPECIFICATION.md` §7 asks for a chain of trust over the kernel image. A hash of the
//! running code cannot be baked into the same image (that would be self-referential), so
//! the honest design is:
//!
//! * every boot prints the **measured** hash of `.text` on COM1, which is what an
//!   operator or a CI job pins;
//! * enforcement is active only when the build supplies `KOS_EXPECTED_TEXT_HASH`
//!   (a post-link step or CI rerun can pass the previously measured value), in which case
//!   a mismatch triggers lockdown.
//!
//! Previously this check was stubbed out (`if true { return true; }`) while the
//! documentation claimed it was active.

use crate::panic::lockdown;
use crate::println;

extern "C" {
    static __text_start: u8;
    static __text_end: u8;
}

/// FNV-1a over the executable section. Chosen over the old djb2 simply because it is
/// 64-bit and therefore has a sane collision probability for an image this size.
fn fnv1a_64(start: *const u8, len: usize) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for i in 0..len {
        let byte = unsafe { core::ptr::read_volatile(start.add(i)) };
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

pub const EXPECTED: Option<u64> = parse_hex_u64(option_env!("KOS_EXPECTED_TEXT_HASH"));

const fn parse_hex_u64(value: Option<&str>) -> Option<u64> {
    let text = match value {
        Some(text) => text.as_bytes(),
        None => return None,
    };
    if text.is_empty() {
        return None;
    }
    let mut index = 0;
    // Tolerate an optional 0x prefix.
    if text.len() > 2 && text[0] == b'0' && (text[1] == b'x' || text[1] == b'X') {
        index = 2;
    }
    let mut result: u64 = 0;
    while index < text.len() {
        let digit = match text[index] {
            b'0'..=b'9' => text[index] - b'0',
            b'a'..=b'f' => text[index] - b'a' + 10,
            b'A'..=b'F' => text[index] - b'A' + 10,
            _ => return None,
        };
        result = (result << 4) | digit as u64;
        index += 1;
    }
    Some(result)
}

/// Measures `.text`, prints the digest, and enforces the expectation when one is pinned.
pub unsafe fn verify_text_hash() -> u64 {
    let start = &__text_start as *const u8;
    let end = &__text_end as *const u8;
    let len = end.offset_from(start) as usize;
    let measured = fnv1a_64(start, len);

    println!(
        "[OK] BUILD INTEGRITY: .text {} KiB, FNV1a-64 {:#018x}",
        len / 1024,
        measured
    );
    match EXPECTED {
        Some(expected) if expected != measured => {
            println!("[FATAL] BUILD HASH MISMATCH (expected {:#018x})", expected);
            println!("        CHAIN OF TRUST BROKEN - REFUSING TO RUN");
            lockdown("build hash mismatch");
        }
        Some(expected) => {
            println!("[OK] BUILD HASH PINNED AND VERIFIED ({:#018x})", expected);
        }
        None => {
            println!("[--] BUILD HASH UNPINNED (pin KOS_EXPECTED_TEXT_HASH for enforcement)");
        }
    }
    measured
}
