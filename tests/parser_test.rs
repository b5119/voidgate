#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for blocklist payload parsing: hosts format, plain lists,
//! comments, header entries, junk, and normalisation.

use voidgate::blocklists::parser::{parse, parse_bytes};

#[test]
fn hosts_format_lines_yield_domains() {
    let domains =
        parse("0.0.0.0 ads.example.com\n127.0.0.1 tracker.example.org\n::1 ipv6.example.net\n");
    assert_eq!(domains.len(), 3);
    assert!(domains.contains("ads.example.com"));
    assert!(domains.contains("tracker.example.org"));
    assert!(domains.contains("ipv6.example.net"));
}

#[test]
fn plain_domain_list_lines_yield_domains() {
    let domains = parse("ads.example.com\ntracker.example.org\n\n   \n");
    assert_eq!(domains.len(), 2);
    assert!(domains.contains("ads.example.com"));
    assert!(domains.contains("tracker.example.org"));
}

#[test]
fn multiple_domains_on_one_hosts_line_are_kept() {
    let domains = parse("0.0.0.0 one.example two.example three.example\n");
    assert_eq!(domains.len(), 3);
    assert!(domains.contains("one.example"));
    assert!(domains.contains("three.example"));
}

#[test]
fn inline_and_full_line_comments_are_stripped() {
    let domains = parse(
        "# full-line comment\n0.0.0.0 ads.example.com # inline comment\nother.example#nospace\n",
    );
    assert_eq!(domains.len(), 2);
    assert!(domains.contains("ads.example.com"));
    assert!(domains.contains("other.example"));
}

#[test]
fn hosts_header_entries_are_skipped() {
    let domains = parse(concat!(
        "127.0.0.1 localhost\n",
        "127.0.0.1 localhost.localdomain\n",
        "255.255.255.255 broadcasthost\n",
        "127.0.0.1 local\n",
        "::1 localhost\n",
        "::1 ip6-localhost\n",
        "::1 ip6-loopback\n",
        "127.0.0.1 localhost.localdomain # comment\n",
    ));
    assert!(domains.is_empty(), "unexpected domains: {domains:?}");
}

#[test]
fn bare_ip_lines_contribute_no_domains() {
    // 0.0.0.0 as a "domain" and as a lone LHS must both be dropped.
    assert!(parse("0.0.0.0\n").is_empty());
    assert!(parse("0.0.0.0 0.0.0.0\n").is_empty());
    assert!(parse("1.2.3.4 5.6.7.8\n").is_empty());
}

#[test]
fn normalisation_lowercases_and_strips_wildcards_and_trailing_dots() {
    let domains = parse("0.0.0.0 ADS.Example.COM.\n0.0.0.0 *.wild.example.com\n");
    assert_eq!(domains.len(), 2);
    assert!(domains.contains("ads.example.com"));
    assert!(domains.contains("wild.example.com"));
}

#[test]
fn punycode_is_preserved_as_ascii_lowercase() {
    let domains = parse("0.0.0.0 XN--BCHER-KVA.example\n");
    assert!(domains.contains("xn--bcher-kva.example"));
    assert_eq!(domains.len(), 1);
}

#[test]
fn junk_lines_and_tokens_are_ignored() {
    let domains = parse(concat!(
        "!!!not a domain!!!\n",
        "version 1.0 checksum abc\n",
        "..bad..label..\n",
        "a..b.example\n",
        "-bad-.example.\n",
        "good.example\n",
    ));
    // "version" is single-label junk, "a..b.example"/"..bad..label.." have
    // empty labels, "-bad-.example" has a hyphen-terminated label — all must
    // be dropped; only well-formed names survive.
    assert!(domains.contains("good.example"));
    assert!(!domains.iter().any(|d| d.contains('!')));
    assert!(!domains.contains("version"));
    assert!(!domains.contains("a..b.example"));
    assert!(!domains.contains("bad..label"));
    assert!(!domains.iter().any(|d| d.contains("-bad-")));
}

#[test]
fn comment_only_and_empty_input_yield_nothing() {
    assert!(parse("").is_empty());
    assert!(parse("\n\n\n").is_empty());
    assert!(parse("# just a comment\n").is_empty());
}

#[test]
fn parse_bytes_handles_lossy_utf8() {
    let mut payload = b"0.0.0.0 ads.example\n".to_vec();
    payload.push(0xFF); // invalid UTF-8 byte is replaced, parse continues
    let domains = parse_bytes(&payload);
    assert!(domains.contains("ads.example"));
}

#[test]
fn parsing_is_idempotent_over_duplicates() {
    let domains = parse("0.0.0.0 dup.example\ndup.example\ndup.example\n");
    assert_eq!(domains.len(), 1);
}
