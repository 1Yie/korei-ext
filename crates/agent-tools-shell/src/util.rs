//! UTF-8-safe truncation helpers.
//!
//! `String::truncate(n)` and `&s[..byte_idx]` panic when `n`/`byte_idx` lands
//! inside a multi-byte char — CJK/emoji tool output hits this on the
//! truncation path (release profile is `panic = abort`, so it kills the
//! process). These helpers round the byte index down to a char boundary.

/// Largest byte index `<= idx` that sits on a UTF-8 char boundary in `s`.
/// `idx` is clamped to `s.len()` first, so `floor(s, usize::MAX)` is safe.
pub fn floor_char_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// `s[..idx]` that never panics — clamps `idx` down to a char boundary.
pub fn head(s: &str, idx: usize) -> &str {
    &s[..floor_char_boundary(s, idx)]
}

/// `s[idx..]` that never panics — clamps `idx` down to a char boundary.
/// Note: for a *tail* slice you usually want the byte index rounded the
/// other way; use [`tail`] for `s[len-n..]`-style cuts.
pub fn from(s: &str, idx: usize) -> &str {
    &s[floor_char_boundary(s, idx)..]
}

/// `s[len-n..]` that never panics — rounds the start index UP to the next
/// char boundary so the tail keeps `<= n` bytes without splitting a char.
pub fn tail(s: &str, n: usize) -> &str {
    let len = s.len();
    if n >= len {
        return s;
    }
    let mut start = len - n;
    while start < len && !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

/// `String::truncate` that never panics — rounds `n` down to a boundary.
pub fn truncate(s: &mut String, n: usize) {
    let b = floor_char_boundary(s, n);
    s.truncate(b);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_math() {
        // a(1) é(2) 中(3) b(1) → byte layout: a|é é|中 中 中|b → len 7
        let s = "aé中b";
        assert_eq!(floor_char_boundary(s, 0), 0);
        assert_eq!(floor_char_boundary(s, 1), 1); // after 'a'
        assert_eq!(floor_char_boundary(s, 2), 1); // inside 'é' → down to 1
        assert_eq!(floor_char_boundary(s, 3), 3); // after 'é'
        assert_eq!(floor_char_boundary(s, 5), 3); // inside '中' → down to 3
        assert_eq!(floor_char_boundary(s, 6), 6); // after '中'
        assert_eq!(floor_char_boundary(s, 99), 7); // clamped to len
    }

    #[test]
    fn head_tail_never_panic() {
        // byte layout: 中(0-2) 文(3-5) a(6) b(7) c(8) → len 9
        let s = "中文abc";
        assert_eq!(head(s, 4), "中"); // 4 is mid-文 → down to 3 → "中"
        assert_eq!(tail(s, 3), "abc"); // len-3=6 → 'a' boundary → "abc"
        assert_eq!(tail(s, 6), "文abc"); // len-6=3 → '文' boundary → "文abc"
        assert_eq!(tail(s, 7), "文abc"); // len-7=2 mid-中 → up to 3 → "文abc"
        assert_eq!(tail(s, 9), "中文abc"); // n>=len → whole string
        let mut owned = "中文abc".to_string();
        truncate(&mut owned, 4);
        assert_eq!(owned, "中"); // 4 mid-文 → "中"
    }

    #[test]
    fn ascii_unchanged() {
        let s = "hello world";
        assert_eq!(head(s, 5), "hello");
        assert_eq!(tail(s, 5), "world");
    }
}
