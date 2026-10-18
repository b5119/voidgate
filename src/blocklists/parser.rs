//! Parsing of blocklist payloads (StevenBlack hosts format and plain domain
//! lists) into normalised domain sets.
//!
//! Normalisation rules:
//! - inline `#` comments are stripped, then the line is tokenised on spaces;
//! - a leading IP (hosts format) is consumed as the LHS and any remaining
//!   tokens are candidate domains;
//! - tokens are lowercased, leading `*.` and trailing `.` are removed;
//! - `localhost`, `localhost.localdomain`, `broadcasthost`, `local`, and
//!   anything starting with `ip6-` are skipped, as are IP literals
//!   (so a bare `0.0.0.0` line contributes nothing);
//! - junk (empty labels, illegal characters, single-label names such as bare
//!   TLDs) is dropped;
//! - punycode (`xn--…`) is kept as-is (ASCII lowercase only).

use std::collections::HashSet;
use std::net::IpAddr;

/// Parses blocklist `text` into a set of normalised domains.
///
/// Handles both StevenBlack hosts lines (`0.0.0.0 example.com`, possibly with
/// several domains per line) and plain one-domain-per-line lists.
///
/// # Examples
///
/// ```
/// # use voidgate::blocklists::parser::parse;
/// let domains = parse("0.0.0.0 ads.example # inline comment\ntracker.example\n");
/// assert!(domains.contains("ads.example"));
/// assert!(domains.contains("tracker.example"));
/// ```
#[must_use]
pub fn parse(text: &str) -> HashSet<String> {
    let mut domains = HashSet::new();
    for line in text.lines() {
        let content = match line.split_once('#') {
            Some((before_comment, _)) => before_comment,
            None => line,
        };
        let mut tokens = content.split_whitespace().peekable();
        // Hosts format: consume the LHS address (this also makes a bare
        // "0.0.0.0" line contribute no domain).
        if let Some(first) = tokens.peek() {
            if first.parse::<IpAddr>().is_ok() {
                let _ = tokens.next();
            }
        }
        for token in tokens {
            if let Some(domain) = normalize(token) {
                domains.insert(domain);
            }
        }
    }
    domains
}

/// Lossy-UTF-8 variant of [`parse`] for cache files with unknown encoding.
///
/// # Examples
///
/// ```
/// # use voidgate::blocklists::parser::parse_bytes;
/// let domains = parse_bytes(b"0.0.0.0 ads.example\n");
/// assert!(domains.contains("ads.example"));
/// ```
#[must_use]
pub fn parse_bytes(bytes: &[u8]) -> HashSet<String> {
    parse(&String::from_utf8_lossy(bytes))
}

/// Normalises one whitespace-delimited token into a storable domain.
///
/// Returns `None` for header entries, IP literals, single-label names, and
/// anything with empty or illegal labels.
fn normalize(token: &str) -> Option<String> {
    let lowered = token.to_ascii_lowercase();
    let candidate = lowered.trim_start_matches("*.").trim_end_matches('.');
    if candidate.is_empty() {
        return None;
    }
    if candidate.parse::<IpAddr>().is_ok() {
        return None;
    }
    if is_skipped_header_entry(candidate) {
        return None;
    }
    // Single-label tokens (bare TLDs, header words like "version") are junk;
    // the store also refuses to match a bare TLD regardless.
    if !candidate.contains('.') {
        return None;
    }
    let labels_ok = candidate.split('.').all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            // DNS labels must start and end with an alphanumeric.
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    });
    if !labels_ok {
        return None;
    }
    Some(candidate.to_owned())
}

/// Hosts-file boilerplate that must never become a blocked domain.
fn is_skipped_header_entry(candidate: &str) -> bool {
    matches!(
        candidate,
        "localhost" | "localhost.localdomain" | "broadcasthost" | "local"
    ) || candidate.starts_with("ip6-")
}
