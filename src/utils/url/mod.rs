pub mod api;
pub mod api_call;
pub mod expected_errors;
pub mod relationship;
pub mod transform;
pub mod types;

pub use transform::*;
pub use types::*;

/// Collapses accidental double slashes (`//`) introduced by parameter
/// substitution in the URL **path**, while preserving the `scheme://` and the
/// query string. A query value may legitimately contain `//` (e.g. an embedded
/// URL passed as a filter), so only the segment before the first `?` is
/// normalised.
pub fn collapse_path_double_slashes(url: &str) -> String {
    // Locate the start of the path: just after `scheme://`, or 0 if no scheme.
    let path_start = url.find("://").map(|i| i + 3).unwrap_or(0);
    let (prefix, rest) = url.split_at(path_start);
    let (path, query) = match rest.find('?') {
        Some(q) => (&rest[..q], &rest[q..]),
        None => (rest, ""),
    };
    format!("{}{}{}", prefix, collapse_slash_runs(path), query)
}

/// Collapses every run of consecutive `/` in `s` down to a single `/`,
/// preserving a leading and trailing slash. A single-pass scan, unlike
/// `str::replace("//", "/")` which only removes *pairs* (`a///b` → `a//b`).
fn collapse_slash_runs(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_slash = false;
    for c in s.chars() {
        let is_slash = c == '/';
        if !(is_slash && prev_slash) {
            out.push(c);
        }
        prev_slash = is_slash;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::collapse_path_double_slashes;

    #[test]
    fn collapses_path_but_preserves_scheme_and_query() {
        assert_eq!(
            collapse_path_double_slashes("https://host//a//b"),
            "https://host/a/b"
        );
        // Scheme slashes preserved.
        assert_eq!(
            collapse_path_double_slashes("https://host/a"),
            "https://host/a"
        );
        // "//" inside a query value must NOT be collapsed.
        assert_eq!(
            collapse_path_double_slashes("https://host//a?u=http://x//y"),
            "https://host/a?u=http://x//y"
        );
        // No scheme: still collapse path, keep query.
        assert_eq!(collapse_path_double_slashes("a//b?x=//z"), "a/b?x=//z");
    }

    // Runs of 3+ slashes collapse to a single slash (regression: the old
    // `replace("//", "/")` only removed pairs, so `a///b` stayed `a//b`).
    #[test]
    fn collapses_runs_of_three_or_more_slashes() {
        assert_eq!(
            collapse_path_double_slashes("https://host/a///b"),
            "https://host/a/b"
        );
        assert_eq!(
            collapse_path_double_slashes("https://host/a////b"),
            "https://host/a/b"
        );
        // Scheme `://` is preserved even when the path immediately starts with a run.
        assert_eq!(
            collapse_path_double_slashes("https://host///a"),
            "https://host/a"
        );
        // A run inside a query value is still left untouched.
        assert_eq!(
            collapse_path_double_slashes("https://host/a?u=http://x///y"),
            "https://host/a?u=http://x///y"
        );
    }
}
