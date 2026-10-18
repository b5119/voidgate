#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for the policy engine: CIDR longest-prefix client
//! resolution and allow > deny > blocklist > forward decisions.

mod common;

use std::collections::HashSet;
use std::net::IpAddr;

use voidgate::blocklists::BlocklistStore;
use voidgate::config::{AppConfig, ConfigError};
use voidgate::policy::{decide, Decision, PolicyEngine, DEFAULT_POLICY_NAME};

/// Parses policy-focused YAML into an [`AppConfig`] (no validation needed:
/// [`PolicyEngine::from_config`] is infallible).
fn config(yaml: &str) -> AppConfig {
    serde_yaml_ng::from_str(yaml).expect("test yaml should parse")
}

/// Builds an engine from policy-focused YAML.
fn engine(yaml: &str) -> PolicyEngine {
    PolicyEngine::from_config(&config(yaml))
}

/// Parses a test address.
fn ip(text: &str) -> IpAddr {
    text.parse().expect("test address should parse")
}

/// Builds a store from `(list name, domains)` pairs.
fn store(entries: &[(&str, &[&str])]) -> BlocklistStore {
    let mut store = BlocklistStore::new();
    for (name, domains) in entries {
        store.insert(*name, domains.to_vec());
    }
    store
}

#[test]
fn longest_prefix_wins_for_overlapping_cidrs() {
    // /8 is declared before the more specific ranges: sorting, not config
    // order, must decide the winner.
    let engine = engine(
        r#"
policies:
  - { name: wide, match: ["10.0.0.0/8"], blocklists: ["ads"] }
  - { name: narrow, match: ["10.1.2.0/24"], blocklists: ["ads"] }
  - { name: host, match: ["10.1.2.3/32"], blocklists: ["ads"] }
default_policy: {}
"#,
    );

    assert_eq!(engine.resolve(ip("10.0.0.1")).name(), "wide");
    assert_eq!(engine.resolve(ip("10.1.2.9")).name(), "narrow");
    assert_eq!(engine.resolve(ip("10.1.2.3")).name(), "host");
    assert_eq!(engine.resolve(ip("10.255.255.255")).name(), "wide");
    assert_eq!(engine.resolve(ip("11.0.0.1")).name(), DEFAULT_POLICY_NAME);
}

#[test]
fn slash32_and_slash128_match_exactly() {
    let engine = engine(
        r#"
policies:
  - { name: host4, match: ["172.16.5.5/32"] }
  - { name: host6, match: ["2001:db8::5/128"] }
default_policy: {}
"#,
    );

    assert_eq!(engine.resolve(ip("172.16.5.5")).name(), "host4");
    assert_eq!(engine.resolve(ip("172.16.5.6")).name(), DEFAULT_POLICY_NAME);
    assert_eq!(engine.resolve(ip("2001:db8::5")).name(), "host6");
    assert_eq!(
        engine.resolve(ip("2001:db8::6")).name(),
        DEFAULT_POLICY_NAME
    );
}

#[test]
fn ipv4_mapped_ipv6_client_resolves_as_ipv4() {
    let engine = engine(
        r#"
policies:
  - { name: lan, match: ["192.168.1.0/24"] }
default_policy: {}
"#,
    );

    assert_eq!(engine.resolve(ip("::ffff:192.168.1.77")).name(), "lan");
    assert_eq!(
        engine.resolve(ip("::ffff:8.8.8.8")).name(),
        DEFAULT_POLICY_NAME
    );
}

#[test]
fn ipv4_mapped_cidrs_are_canonicalised() {
    // ::ffff:10.0.0.0/104 is 96 + 8 bits of IPv4, i.e. 10.0.0.0/8.
    let engine = engine(
        r#"
policies:
  - { name: mapped, match: ["::ffff:10.0.0.0/104"] }
default_policy: {}
"#,
    );

    assert_eq!(engine.resolve(ip("10.0.0.7")).name(), "mapped");
    assert_eq!(engine.resolve(ip("::ffff:10.0.0.7")).name(), "mapped");
    assert_eq!(engine.resolve(ip("11.0.0.7")).name(), DEFAULT_POLICY_NAME);
}

#[test]
fn ipv6_cidr_matches_only_its_range() {
    let engine = engine(
        r#"
policies:
  - { name: docs, match: ["2001:db8::/32"] }
default_policy: {}
"#,
    );

    assert_eq!(engine.resolve(ip("2001:db8:abcd::1")).name(), "docs");
    assert_eq!(
        engine.resolve(ip("2001:db9::1")).name(),
        DEFAULT_POLICY_NAME
    );
}

#[test]
fn unmatched_clients_use_the_default_policy() {
    let engine = engine(
        r#"
policies:
  - { name: lan, match: ["10.0.0.0/8"], blocklists: ["ads"] }
default_policy: { blocklists: ["ads"], denylist: ["denied.example"] }
"#,
    );
    let store = store(&[("ads", &["ads.example"])]);

    let policy = engine.resolve(ip("203.0.113.9"));
    assert_eq!(policy.name(), DEFAULT_POLICY_NAME);
    assert_eq!(decide(policy, "denied.example", &store), Decision::Denied);
    assert_eq!(
        decide(policy, "ads.example", &store),
        Decision::Blocked {
            list: "ads".to_owned()
        }
    );
    assert_eq!(decide(policy, "other.example", &store), Decision::Forward);
}

#[test]
fn precedence_is_allow_then_deny_then_blocklist_then_forward() {
    let engine = engine(
        r#"
policies:
  - name: lan
    match: ["10.0.0.0/8"]
    blocklists: ["ads"]
    allowlist: ["allow.example", "both.example"]
    denylist: ["deny.example", "bothdeny.example"]
default_policy: {}
"#,
    );
    let store = store(&[("ads", &["ads.example", "both.example", "bothdeny.example"])]);
    let policy = engine.resolve(ip("10.0.0.5"));

    // Allowlist beats everything, even a blocklist hit.
    assert_eq!(decide(policy, "allow.example", &store), Decision::Allowed);
    assert_eq!(decide(policy, "both.example", &store), Decision::Allowed);
    // Denylist beats the blocklist.
    assert_eq!(decide(policy, "deny.example", &store), Decision::Denied);
    assert_eq!(decide(policy, "bothdeny.example", &store), Decision::Denied);
    // Blocklist beats forward.
    assert_eq!(
        decide(policy, "ads.example", &store),
        Decision::Blocked {
            list: "ads".to_owned()
        }
    );
    // Everything else falls through.
    assert_eq!(decide(policy, "other.example", &store), Decision::Forward);
}

#[test]
fn allow_subdomain_beats_blocklist() {
    let engine = engine(
        r#"
policies:
  - name: lan
    match: ["10.0.0.0/8"]
    blocklists: ["ads"]
    allowlist: ["example.com"]
default_policy: {}
"#,
    );
    let store = store(&[("ads", &["ads.example.com", "other.org"])]);
    let policy = engine.resolve(ip("10.0.0.5"));

    assert_eq!(decide(policy, "ads.example.com", &store), Decision::Allowed);
    assert_eq!(decide(policy, "example.com", &store), Decision::Allowed);
    // A domain outside the allow entry still consults the blocklist.
    assert_eq!(
        decide(policy, "other.org", &store),
        Decision::Blocked {
            list: "ads".to_owned()
        }
    );
}

#[test]
fn more_specific_deny_does_not_beat_allow() {
    let engine = engine(
        r#"
policies:
  - name: lan
    match: ["10.0.0.0/8"]
    allowlist: ["example.com"]
    denylist: ["a.example.com"]
default_policy: {}
"#,
    );
    let store = BlocklistStore::new();
    let policy = engine.resolve(ip("10.0.0.5"));

    // The allow entry wins for the whole subtree, even where a more specific
    // deny entry would otherwise apply.
    assert_eq!(decide(policy, "a.example.com", &store), Decision::Allowed);
    assert_eq!(decide(policy, "b.example.com", &store), Decision::Allowed);
    assert_eq!(decide(policy, "example.com", &store), Decision::Allowed);
    assert_eq!(decide(policy, "other.org", &store), Decision::Forward);
}

#[test]
fn allow_wins_when_its_entry_is_more_specific_than_deny() {
    let engine = engine(
        r#"
policies:
  - name: lan
    match: ["10.0.0.0/8"]
    allowlist: ["deep.example.com"]
    denylist: ["example.com"]
default_policy: {}
"#,
    );
    let store = BlocklistStore::new();
    let policy = engine.resolve(ip("10.0.0.5"));

    assert_eq!(
        decide(policy, "deep.example.com", &store),
        Decision::Allowed
    );
    assert_eq!(
        decide(policy, "other.example.com", &store),
        Decision::Denied
    );
    assert_eq!(decide(policy, "example.com", &store), Decision::Denied);
}

#[test]
fn label_boundaries_are_respected_in_allow_and_deny() {
    let engine = engine(
        r#"
policies:
  - name: lan
    match: ["10.0.0.0/8"]
    allowlist: ["safe.org"]
    denylist: ["ads.com"]
default_policy: {}
"#,
    );
    let store = BlocklistStore::new();
    let policy = engine.resolve(ip("10.0.0.5"));

    assert_eq!(decide(policy, "ads.com", &store), Decision::Denied);
    assert_eq!(decide(policy, "sub.ads.com", &store), Decision::Denied);
    // The classic suffix bug: ads.com must not match notads.com.
    assert_eq!(decide(policy, "notads.com", &store), Decision::Forward);

    assert_eq!(decide(policy, "safe.org", &store), Decision::Allowed);
    assert_eq!(decide(policy, "sub.safe.org", &store), Decision::Allowed);
    assert_eq!(decide(policy, "unsafe.org", &store), Decision::Forward);
}

#[test]
fn bare_tld_entries_never_match() {
    let engine = engine(
        r#"
policies:
  - name: lan
    match: ["10.0.0.0/8"]
    allowlist: ["com"]
    denylist: ["example.com"]
default_policy: {}
"#,
    );
    let store = BlocklistStore::new();
    let policy = engine.resolve(ip("10.0.0.5"));

    // `com` in an allowlist would otherwise allow the entire TLD.
    assert_eq!(decide(policy, "example.com", &store), Decision::Denied);
    assert_eq!(decide(policy, "com", &store), Decision::Forward);
}

#[test]
fn blocked_reports_the_first_matching_list_name() {
    let engine = engine(
        r#"
policies:
  - name: lan
    match: ["10.0.0.0/8"]
    blocklists: ["first", "second"]
default_policy: {}
"#,
    );
    let store = store(&[
        ("first", &["both.example"]),
        ("second", &["target.example", "both.example"]),
    ]);
    let policy = engine.resolve(ip("10.0.0.5"));

    assert_eq!(
        decide(policy, "target.example", &store),
        Decision::Blocked {
            list: "second".to_owned()
        }
    );
    // Config order decides which name is reported when both match.
    assert_eq!(
        decide(policy, "both.example", &store),
        Decision::Blocked {
            list: "first".to_owned()
        }
    );
}

#[test]
fn allow_and_deny_entries_are_normalised() {
    let engine = engine(
        r#"
policies:
  - name: lan
    match: ["10.0.0.0/8"]
    allowlist: ["*.Wild.Example.", " UPPER.ORG "]
    denylist: ["Deny.NET."]
default_policy: {}
"#,
    );
    let store = BlocklistStore::new();
    let policy = engine.resolve(ip("10.0.0.5"));

    assert_eq!(decide(policy, "wild.example", &store), Decision::Allowed);
    assert_eq!(decide(policy, "a.wild.example", &store), Decision::Allowed);
    assert_eq!(decide(policy, "upper.org", &store), Decision::Allowed);
    assert_eq!(decide(policy, "sub.upper.org", &store), Decision::Allowed);
    assert_eq!(decide(policy, "deny.net", &store), Decision::Denied);
    assert_eq!(decide(policy, "x.deny.net", &store), Decision::Denied);
}

#[test]
fn decide_is_safe_on_odd_input() {
    let engine = engine(
        r#"
policies:
  - name: lan
    match: ["10.0.0.0/8"]
    blocklists: ["ads"]
    allowlist: ["safe.example"]
    denylist: ["denied.example"]
default_policy: {}
"#,
    );
    let store = store(&[("ads", &["ads.example"])]);
    let policy = engine.resolve(ip("10.0.0.5"));

    // decide() assumes normalised input but must never panic on anything else.
    assert_eq!(decide(policy, "", &store), Decision::Forward);
    assert_eq!(decide(policy, "localhost", &store), Decision::Forward);
    assert_eq!(decide(policy, "a..b", &store), Decision::Forward);
    assert_eq!(decide(policy, ".com", &store), Decision::Forward);
    // Unnormalised input simply fails to match (the handler normalises first):
    // allow/deny sets are compared against the normalised form, so uppercase
    // names miss even though the blocklist store itself is case-insensitive.
    assert_eq!(decide(policy, "SAFE.EXAMPLE", &store), Decision::Forward);
    assert_eq!(decide(policy, "DENIED.EXAMPLE.", &store), Decision::Forward);
}

#[test]
fn policies_reference_only_declared_blocklists() {
    let yaml = r#"
server: { allowed_clients: ["127.0.0.0/8"] }
blocklists:
  lists:
    - { name: ads, type: file, source: "ads.txt" }
    - { name: trackers, type: file, source: "trackers.txt" }
policies:
  - { name: lan, match: ["10.0.0.0/8"], blocklists: ["ads"] }
  - { name: guests, match: ["10.1.0.0/16"], blocklists: ["ads", "trackers"] }
default_policy: { blocklists: ["ads"] }
"#;
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let path = common::write_config(dir.path(), yaml);
    let loaded = AppConfig::load(&path).expect("config should load");

    let declared: HashSet<&str> = loaded
        .config
        .blocklists
        .lists
        .iter()
        .map(|list| list.name.as_str())
        .collect();
    for policy in &loaded.config.policies {
        for referenced in &policy.blocklists {
            assert!(
                declared.contains(referenced.as_str()),
                "policy `{}` references undeclared list `{referenced}`",
                policy.name
            );
        }
    }
    for referenced in &loaded.config.default_policy.blocklists {
        assert!(declared.contains(referenced.as_str()));
    }

    // And the invariant is enforced, not merely true of this fixture.
    let bad = yaml.replace(r#"["ads", "trackers"]"#, r#"["ads", "missing"]"#);
    let bad_path = common::write_config(dir.path(), &bad);
    let error = AppConfig::load(&bad_path).expect_err("unknown reference must fail");
    assert!(
        matches!(error, ConfigError::UnknownBlocklist { .. }),
        "expected UnknownBlocklist, got {error:?}"
    );
}
