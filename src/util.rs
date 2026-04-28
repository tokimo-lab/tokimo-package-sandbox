//! Small string utilities for sandbox naming.

/// Sanitize a name for use as a path segment (e.g. under a per-session
/// data directory).
///
/// **Legacy fallback** — kept for defense-in-depth. Callers SHOULD
/// validate names before they reach the sandbox (rejecting path
/// separators, control chars, leading dots, overlong names) so this
/// helper is normally unused. It is exposed for consumers that don't
/// have such an upstream validator.
///
/// Replaces path separators, control characters, and whitespace with
/// `_`. Empty / dot-only names fall back to a deterministic
/// placeholder.
pub fn safe_session_name(name: &str) -> String {
    let cleaned: String = name
        .trim()
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() || c.is_whitespace() {
                '_'
            } else {
                c
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "unnamed".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::safe_session_name;

    #[test]
    fn safe_name_strips_separators() {
        assert_eq!(safe_session_name("a/b\\c"), "a_b_c");
        assert_eq!(safe_session_name("hello world"), "hello_world");
        assert_eq!(safe_session_name(""), "unnamed");
        assert_eq!(safe_session_name(".."), "unnamed");
    }
}
