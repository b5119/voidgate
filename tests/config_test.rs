#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for configuration loading and validation.

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use ipnet::IpNet;
use voidgate::config::{AclAction, AppConfig, ConfigError, LoadedConfig};

/// Loads `yaml` from a temporary directory.
fn load(yaml: &str) -> Result<LoadedConfig, ConfigError> {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let path = common::write_config(dir.path(), yaml);
    AppConfig::load(&path)
}

#[test]
fn example_config_loads_without_warnings() {
    let loaded = AppConfig::load(Path::new("config.example.yaml"))
        .expect("config.example.yaml must be valid");
    assert!(
        loaded.warnings.is_empty(),
        "example config should not warn: {:?}",
        loaded.warnings
    );

    let config = loaded.config;
    assert_eq!(config.server.port, 5353);
    assert_eq!(config.server.listen, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(config.server.acl_action, AclAction::Refuse);
    assert_eq!(config.server.sinkhole_ttl_secs, 60);
    assert_eq!(config.server.max_concurrent_queries, 256);
    assert_eq!(config.blocklists.refresh_interval_secs, 86_400);
    assert_eq!(config.storage.retention_days, 30);
    assert!(config.storage.log_queries);
    assert_eq!(config.policies.len(), 2);
    assert_eq!(config.policies[0].name, "kids");
    // The /32 entries and the /24 all sit inside allowed_clients.
    assert!(config
        .server
        .client_allowed(&"192.168.1.50".parse().unwrap()));
}

#[test]
fn defaults_are_applied_for_absent_sections() {
    let yaml = r#"
server:
  allowed_clients: ["10.0.0.0/8"]
default_policy: {}
"#;
    let loaded = load(yaml).expect("minimal config should load");
    let config = loaded.config;

    assert_eq!(config.server.port, 5353);
    assert_eq!(config.server.listen, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(
        config.server.upstream,
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
    );
    assert_eq!(config.server.upstream_port, 53);
    assert_eq!(config.server.timeout_ms, 2000);
    assert_eq!(config.server.max_concurrent_queries, 256);
    assert_eq!(config.server.sinkhole_ttl_secs, 60);
    assert_eq!(config.server.acl_action, AclAction::Refuse);
    assert_eq!(config.blocklists.cache_dir, Path::new("cache"));
    assert_eq!(config.blocklists.refresh_interval_secs, 86_400);
    assert_eq!(config.blocklists.fetch_timeout_secs, 30);
    assert_eq!(config.blocklists.max_fetch_bytes, 52_428_800);
    assert_eq!(config.blocklists.min_retained_percent, 10);
    assert_eq!(config.storage.db_path, Path::new("voidgate.db"));
    assert!(config.storage.log_queries);
    assert_eq!(config.storage.retention_days, 30);
    assert_eq!(config.log_level, "info");

    // Empty default policy and no policies are warnings, not errors.
    assert!(
        loaded
            .warnings
            .iter()
            .any(|w| w.contains("default_policy.blocklists is empty")),
        "warnings: {:?}",
        loaded.warnings
    );
    assert!(
        loaded.warnings.iter().any(|w| w.contains("no policies")),
        "warnings: {:?}",
        loaded.warnings
    );
}

#[test]
fn missing_allowed_clients_is_rejected() {
    let yaml = "default_policy: {}\n";
    let err = load(yaml).expect_err("missing allowed_clients must fail");
    assert!(matches!(err, ConfigError::EmptyField { .. }), "{err:?}");
    assert!(err.to_string().contains("server.allowed_clients"));
}

#[test]
fn empty_allowed_clients_is_rejected() {
    let yaml = "server: { allowed_clients: [] }\ndefault_policy: {}\n";
    let err = load(yaml).expect_err("empty allowed_clients must fail");
    assert!(matches!(err, ConfigError::EmptyField { .. }), "{err:?}");
}

#[test]
fn duplicate_match_across_policies_is_rejected() {
    let yaml = r#"
server:
  allowed_clients: ["10.0.0.0/8"]
blocklists:
  lists:
    - name: l
      type: file
      source: "lists/l.txt"
policies:
  - name: a
    match: ["10.1.0.0/24"]
    blocklists: [l]
  - name: b
    match: ["10.1.0.0/24"]
    blocklists: [l]
default_policy: {}
"#;
    let err = load(yaml).expect_err("duplicate match must fail");
    match err {
        ConfigError::DuplicateMatch { net, first, second } => {
            assert_eq!(net, "10.1.0.0/24".parse::<IpNet>().unwrap());
            assert_eq!(first, "a");
            assert_eq!(second, "b");
        }
        other => panic!("expected DuplicateMatch, got {other:?}"),
    }
}

#[test]
fn duplicate_policy_name_is_rejected() {
    let yaml = r#"
server:
  allowed_clients: ["10.0.0.0/8"]
policies:
  - name: same
    match: ["10.1.0.0/24"]
  - name: same
    match: ["10.2.0.0/24"]
default_policy: {}
"#;
    let err = load(yaml).expect_err("duplicate policy name must fail");
    assert!(
        matches!(err, ConfigError::DuplicatePolicy { .. }),
        "{err:?}"
    );
}

#[test]
fn unknown_blocklist_reference_is_rejected() {
    let yaml = r#"
server:
  allowed_clients: ["10.0.0.0/8"]
policies:
  - name: p
    match: ["10.1.0.0/24"]
    blocklists: [nope]
default_policy: {}
"#;
    let err = load(yaml).expect_err("unknown blocklist must fail");
    match err {
        ConfigError::UnknownBlocklist { policy, list } => {
            assert_eq!(policy, "p");
            assert_eq!(list, "nope");
        }
        other => panic!("expected UnknownBlocklist, got {other:?}"),
    }
}

#[test]
fn duplicate_blocklist_name_is_rejected() {
    let yaml = r#"
server:
  allowed_clients: ["10.0.0.0/8"]
blocklists:
  lists:
    - name: dupe
      type: file
      source: "a.txt"
    - name: dupe
      type: file
      source: "b.txt"
default_policy: {}
"#;
    let err = load(yaml).expect_err("duplicate blocklist name must fail");
    assert!(
        matches!(err, ConfigError::DuplicateBlocklist { .. }),
        "{err:?}"
    );
}

#[test]
fn match_outside_allowed_clients_warns() {
    let yaml = r#"
server:
  allowed_clients: ["192.168.1.0/24"]
policies:
  - name: guest
    match: ["172.16.0.0/16"]
default_policy: {}
"#;
    let loaded = load(yaml).expect("outside match is only a warning");
    let warning = loaded
        .warnings
        .iter()
        .find(|w| w.contains("guest"))
        .expect("a warning should mention the policy");
    assert!(warning.contains("172.16.0.0/16"));
    assert!(warning.contains("REFUSED"));
}

#[test]
fn invalid_cidr_is_rejected() {
    let yaml = "server: { allowed_clients: [\"10.0.0.0/33\"] }\ndefault_policy: {}\n";
    let err = load(yaml).expect_err("invalid CIDR must fail");
    assert!(matches!(err, ConfigError::Parse { .. }), "{err:?}");
}

#[test]
fn invalid_acl_action_is_rejected() {
    let yaml =
        "server: { allowed_clients: [\"10.0.0.0/8\"], acl_action: maybe }\ndefault_policy: {}\n";
    let err = load(yaml).expect_err("unknown acl_action must fail");
    assert!(matches!(err, ConfigError::Parse { .. }), "{err:?}");
}

#[test]
fn zero_valued_tunables_are_rejected() {
    for (field, yaml) in [
        ("server.port", "server: { allowed_clients: [\"10.0.0.0/8\"], port: 0 }\ndefault_policy: {}\n"),
        ("server.timeout_ms", "server: { allowed_clients: [\"10.0.0.0/8\"], timeout_ms: 0 }\ndefault_policy: {}\n"),
        ("server.sinkhole_ttl_secs", "server: { allowed_clients: [\"10.0.0.0/8\"], sinkhole_ttl_secs: 0 }\ndefault_policy: {}\n"),
        (
            "server.max_concurrent_queries",
            "server: { allowed_clients: [\"10.0.0.0/8\"], max_concurrent_queries: 0 }\ndefault_policy: {}\n",
        ),
        (
            "blocklists.fetch_timeout_secs",
            "server: { allowed_clients: [\"10.0.0.0/8\"] }\nblocklists: { fetch_timeout_secs: 0 }\ndefault_policy: {}\n",
        ),
        (
            "blocklists.max_fetch_bytes",
            "server: { allowed_clients: [\"10.0.0.0/8\"] }\nblocklists: { max_fetch_bytes: 0 }\ndefault_policy: {}\n",
        ),
    ] {
        let err = load(yaml).expect_err("zero value must fail");
        match &err {
            ConfigError::NonZero { field: got } => assert_eq!(*got, field),
            other => panic!("expected NonZero({field}), got {other:?}"),
        }
    }
}

#[test]
fn min_retained_percent_must_be_1_to_100() {
    for value in [0u32, 101, 999] {
        let yaml = format!(
            "server: {{ allowed_clients: [\"10.0.0.0/8\"] }}\nblocklists: {{ min_retained_percent: {value} }}\ndefault_policy: {{}}\n"
        );
        let err = load(&yaml).expect_err("out-of-range value must fail");
        match &err {
            ConfigError::OutOfRange {
                field,
                value: got,
                min,
                max,
            } => {
                assert_eq!(*field, "blocklists.min_retained_percent");
                assert_eq!(*got, value);
                assert_eq!((*min, *max), (1, 100));
            }
            other => panic!("expected OutOfRange, got {other:?}"),
        }
    }
    // In-range boundary values are accepted.
    for value in [1u32, 10, 100] {
        let yaml = format!(
            "server: {{ allowed_clients: [\"10.0.0.0/8\"] }}\nblocklists: {{ min_retained_percent: {value} }}\ndefault_policy: {{}}\n"
        );
        load(&yaml).unwrap_or_else(|err| panic!("{value} should be accepted: {err}"));
    }
}

#[test]
fn blocklist_names_must_be_cache_safe() {
    // Safe names load fine.
    for name in ["stevenblack", "local-ads", "a_b_c9", "x"] {
        let yaml = format!(
            "server: {{ allowed_clients: [\"10.0.0.0/8\"] }}\nblocklists: {{ lists: [{{ name: \"{name}\", type: file, source: \"x.txt\" }}] }}\ndefault_policy: {{}}\n"
        );
        load(&yaml).unwrap_or_else(|err| panic!("{name} should be accepted: {err}"));
    }
    // Names that could traverse a path or confuse a filesystem are rejected.
    for name in ["../evil", "a/b", "UPPER", "with space", "dot.name", "nämé"] {
        let yaml = format!(
            "server: {{ allowed_clients: [\"10.0.0.0/8\"] }}\nblocklists: {{ lists: [{{ name: \"{name}\", type: file, source: \"x.txt\" }}] }}\ndefault_policy: {{}}\n"
        );
        let err = load(&yaml).expect_err("unsafe name must fail");
        assert!(
            matches!(err, ConfigError::InvalidBlocklistName { .. }),
            "expected InvalidBlocklistName for {name:?}, got {err:?}"
        );
    }
}

#[test]
fn invalid_log_level_is_rejected() {
    let yaml = "server: { allowed_clients: [\"10.0.0.0/8\"] }\ndefault_policy: {}\nlog_level: \"foo=bar\"\n";
    let err = load(yaml).expect_err("invalid log_level must fail");
    assert!(
        matches!(err, ConfigError::InvalidLogLevel { .. }),
        "{err:?}"
    );
}

#[test]
fn unknown_top_level_key_is_rejected() {
    let yaml = "server: { allowed_clients: [\"10.0.0.0/8\"] }\ndefault_policy: {}\ntyopo: true\n";
    let err = load(yaml).expect_err("unknown key must fail");
    assert!(matches!(err, ConfigError::Parse { .. }), "{err:?}");
}

#[test]
fn acl_action_drop_parses() {
    let yaml =
        "server: { allowed_clients: [\"10.0.0.0/8\"], acl_action: drop }\ndefault_policy: {}\n";
    let loaded = load(yaml).expect("acl_action: drop must parse");
    assert_eq!(loaded.config.server.acl_action, AclAction::Drop);
}

#[test]
fn minimal_helper_config_loads() {
    let loaded = load(&common::minimal_config_yaml()).expect("helper config should load");
    assert_eq!(loaded.config.blocklists.lists.len(), 1);
    assert_eq!(loaded.config.blocklists.lists[0].name, "testlist");
}
