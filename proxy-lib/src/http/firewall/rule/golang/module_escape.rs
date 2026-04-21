/// Reverses Go's module path escaping (`golang.org/x/mod/module.EscapePath`).
///
/// Go encodes each uppercase letter as `!` + lowercase so module caches work on
/// case-insensitive filesystems — e.g. `AikidoSec` → `!aikido!sec`. `!a`–`!z` are
/// each replaced by the corresponding uppercase letter; any `!` not followed by a
/// lowercase letter is passed through unchanged.
pub(super) fn go_module_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '!' {
            if let Some(&next) = chars.peek() {
                if next.is_ascii_lowercase() {
                    out.push(next.to_ascii_uppercase());
                    chars.next();
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
#[path = "module_escape_tests.rs"]
mod tests;
