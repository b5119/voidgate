//! Parsing of blocklist payloads (StevenBlack hosts format and plain domain
//! lists) into normalised domain sets.
//!
//! TODO(M2): implement `parse_hosts`, `parse_domains`, and the normalisation
//! rules (lowercase, strip `#` comments, skip `0.0.0.0`/`127.0.0.1` host
//! lines, drop `*.` prefixes and trailing dots).
