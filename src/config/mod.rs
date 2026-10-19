//! Configuration model: parsing `config.yaml`, defaults, and validation.
//!
//! [`AppConfig::load`] is the single entry point that reads YAML from disk.
//! Every other module receives an already-validated [`AppConfig`] (or a slice
//! of it) and never touches the file itself.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod error;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use serde::Deserialize;

pub use error::ConfigError;

/// A parsed configuration together with the non-fatal issues found while
/// validating it.
///
/// Warnings are returned rather than logged so the caller can install the
/// `tracing` subscriber (whose filter comes from `log_level`) first.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// The validated configuration.
    pub config: AppConfig,
    /// Non-fatal issues, e.g. a policy whose `match` CIDRs fall outside
    /// `server.allowed_clients`.
    pub warnings: Vec<String>,
}

/// Top-level configuration file (`config.yaml`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// Listener address, ACL, upstream resolver, and sinkhole settings.
    #[serde(default)]
    pub server: ServerConfig,
    /// Blocklist sources, cache directory, and refresh cadence.
    #[serde(default)]
    pub blocklists: BlocklistsConfig,
    /// Per-client policies. Resolution uses CIDR longest-prefix matching.
    #[serde(default)]
    pub policies: Vec<PolicyConfig>,
    /// Fallback policy for clients that match no entry in [`Self::policies`].
    pub default_policy: DefaultPolicyConfig,
    /// Query log (SQLite) settings.
    #[serde(default)]
    pub storage: StorageConfig,
    /// `tracing` filter directive (`"info"`, `"debug"`, `"voidgate=debug"`, …).
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

/// Listener, ACL, upstream, and sinkhole behaviour.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// Address the UDP/TCP DNS listeners bind to.
    ///
    /// The example config keeps this on loopback; exposing a sinkhole to a
    /// LAN means binding a private address *and* tightening `allowed_clients`.
    pub listen: IpAddr,
    /// UDP/TCP port to listen on (`5353` for development, `53` in production).
    pub port: u16,
    /// CIDR ranges permitted to query the server. Required and must not be
    /// empty: clients outside every range are refused or dropped according to
    /// [`ServerConfig::acl_action`].
    pub allowed_clients: Vec<IpNet>,
    /// What to do with queries from clients outside `allowed_clients`.
    pub acl_action: AclAction,
    /// Upstream recursive resolver address.
    pub upstream: IpAddr,
    /// Upstream resolver port.
    pub upstream_port: u16,
    /// Per-query upstream timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum number of queries accepted concurrently (the listener's
    /// in-flight semaphore). Packets that arrive when every permit is taken
    /// are dropped rather than spawning unbounded tasks. Must be greater
    /// than 0.
    pub max_inflight: usize,
    /// Maximum number of queries forwarded to the upstream resolver at the
    /// same time. When this cap is reached, new forward/allowed queries
    /// receive SERVFAIL immediately; blocked/denied and ACL paths do not
    /// consume an upstream permit. Must be greater than 0.
    pub max_upstream_inflight: usize,
    /// How long, in milliseconds, to wait for in-flight queries to finish
    /// after a shutdown signal before abandoning them. Must be greater
    /// than 0.
    pub shutdown_grace_ms: u64,
    /// Whether the TCP listener is started alongside UDP on the same port.
    pub tcp_enabled: bool,
    /// Idle timeout in milliseconds for a TCP connection: a client that sends
    /// nothing (or a partial frame) for this long is disconnected. Must be
    /// greater than 0.
    pub tcp_idle_timeout_ms: u64,
    /// Maximum number of simultaneous TCP connections; new connections beyond
    /// the cap are closed immediately. Must be greater than 0.
    pub tcp_max_connections: usize,
    /// Maximum number of queries served on one TCP connection before it is
    /// closed. Must be greater than 0.
    pub tcp_max_queries_per_conn: u32,
    /// TTL in seconds attached to sinkhole answers (`0.0.0.0` / `::`).
    pub sinkhole_ttl_secs: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 5353,
            // Deliberately empty: a config that forgets allowed_clients fails
            // closed (validation error) instead of listening for the world.
            allowed_clients: Vec::new(),
            acl_action: AclAction::Refuse,
            upstream: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            upstream_port: 53,
            timeout_ms: 2000,
            max_inflight: 1024,
            max_upstream_inflight: 256,
            shutdown_grace_ms: 2000,
            tcp_enabled: true,
            tcp_idle_timeout_ms: 2000,
            tcp_max_connections: 128,
            tcp_max_queries_per_conn: 100,
            sinkhole_ttl_secs: 60,
        }
    }
}

impl ServerConfig {
    /// Returns `true` if `client` is covered by [`Self::allowed_clients`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::IpAddr;
    /// # use voidgate::config::ServerConfig;
    /// # use ipnet::IpNet;
    /// let cfg = ServerConfig {
    ///     allowed_clients: vec!["192.168.1.0/24".parse::<IpNet>().unwrap()],
    ///     ..ServerConfig::default()
    /// };
    /// let client: IpAddr = "192.168.1.7".parse().unwrap();
    /// assert!(cfg.client_allowed(&client));
    /// ```
    #[must_use]
    pub fn client_allowed(&self, client: &IpAddr) -> bool {
        self.allowed_clients
            .iter()
            .any(|allowed| allowed.contains(client))
    }
}

/// Response (or lack thereof) for clients outside `allowed_clients`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AclAction {
    /// Reply with `REFUSED`.
    #[default]
    Refuse,
    /// Ignore the query entirely (no response is sent).
    Drop,
}

/// Blocklist sources and cache/refresh settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BlocklistsConfig {
    /// Directory `update-lists` writes fetched lists into (atomic
    /// temp-file + rename) and the server reads from at startup.
    pub cache_dir: PathBuf,
    /// How often the running server re-fetches URL lists, renames them into
    /// `cache_dir`, and hot-swaps them via `ArcSwap`.
    ///
    /// `0` disables the periodic refresh; `SIGHUP` still reloads whatever is
    /// in the cache (offline).
    pub refresh_interval_secs: u64,
    /// HTTP timeout for `update-lists` fetches. Must be greater than 0.
    pub fetch_timeout_secs: u64,
    /// Downloads larger than this (bytes) are rejected and the previous cache
    /// file is kept. Must be greater than 0. Default: 50 MiB.
    pub max_fetch_bytes: u64,
    /// A refresh is rejected (previous cache kept) when the new domain count
    /// retains less than this percentage of the previous count — i.e. `10`
    /// rejects downloads that are more than 90% smaller. Allowed 1..=100.
    pub min_retained_percent: u32,
    /// The lists themselves; names must be unique, match `[a-z0-9_-]+`, and
    /// are referenced by policies.
    pub lists: Vec<BlocklistSource>,
}

impl Default for BlocklistsConfig {
    fn default() -> Self {
        Self {
            cache_dir: PathBuf::from("cache"),
            refresh_interval_secs: 86_400,
            fetch_timeout_secs: 30,
            max_fetch_bytes: 52_428_800,
            min_retained_percent: 10,
            lists: Vec::new(),
        }
    }
}

/// One blocklist source (`url` fetched over HTTPS, or a local `file`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlocklistSource {
    /// Unique name policies use to reference this list.
    pub name: String,
    /// How to obtain the list.
    #[serde(rename = "type")]
    pub kind: BlocklistKind,
    /// URL (`type: url`) or filesystem path (`type: file`).
    pub source: String,
}

/// The two supported ways to obtain a blocklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistKind {
    /// Fetch over HTTPS with reqwest/rustls.
    Url,
    /// Read from a local path.
    File,
}

/// A per-client policy: which blocklists apply plus allow/deny overrides.
///
/// Precedence when deciding about a domain is
/// allowlist > denylist > blocklist > forward (see `policy` module).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Unique policy name (used in logs and stats).
    pub name: String,
    /// Client CIDRs this policy applies to. Overlaps between policies are
    /// resolved by longest prefix; an entry duplicated across policies is a
    /// [`ConfigError::DuplicateMatch`].
    #[serde(rename = "match")]
    pub matches: Vec<IpNet>,
    /// Names of the blocklists that apply for these clients.
    #[serde(default)]
    pub blocklists: Vec<String>,
    /// Domains (and all their subdomains) that are never blocked.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Domains (and all their subdomains) that are always blocked.
    #[serde(default)]
    pub denylist: Vec<String>,
}

/// The fallback policy for clients no [`PolicyConfig`] matches.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DefaultPolicyConfig {
    /// Blocklists applied to unmatched clients.
    pub blocklists: Vec<String>,
    /// Allowlist entries (domain and subdomains).
    pub allowlist: Vec<String>,
    /// Denylist entries (domain and subdomains).
    pub denylist: Vec<String>,
}

/// Query log settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StorageConfig {
    /// SQLite database path.
    pub db_path: PathBuf,
    /// `false` disables query rows entirely: no database file is created and
    /// no writer thread is spawned (log calls become no-ops).
    pub log_queries: bool,
    /// Rows older than this many days are pruned at startup and then on the
    /// `prune_interval_secs` schedule. `0` disables pruning.
    pub retention_days: u32,
    /// SQLite `busy_timeout` for the writer and stats connections, in
    /// milliseconds. Must be greater than 0.
    pub busy_timeout_ms: u64,
    /// Capacity of the in-memory queue between query handlers and the writer
    /// thread. When full, new rows are dropped (and counted) rather than
    /// blocking DNS. Must be greater than 0.
    pub queue_capacity: usize,
    /// The writer commits a transaction once this many rows are pending. Must
    /// be greater than 0.
    pub flush_rows: usize,
    /// The writer also commits on this interval, in milliseconds, so a
    /// low-traffic server still persists rows promptly. Must be greater than 0.
    pub flush_interval_ms: u64,
    /// How often the writer thread prunes expired rows, in seconds. Must be
    /// greater than 0 (ignored when `retention_days` is 0).
    pub prune_interval_secs: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("voidgate.db"),
            log_queries: true,
            retention_days: 30,
            busy_timeout_ms: 5000,
            queue_capacity: 8192,
            flush_rows: 256,
            flush_interval_ms: 500,
            prune_interval_secs: 3600,
        }
    }
}

fn default_log_level() -> String {
    "info".to_owned()
}

/// Returns `true` when `name` is safe to embed in a cache filename:
/// non-empty and only `a-z`, `0-9`, `_`, `-`.
///
/// Enforced at config-validation time *and* when cache paths are built
/// (defence in depth against path traversal).
#[must_use]
pub fn is_cache_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

impl AppConfig {
    /// Reads, parses, and validates the config file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] if the file cannot be read,
    /// [`ConfigError::Parse`] if it is not valid configuration YAML, and any
    /// validation error from [`AppConfig::validate`].
    pub fn load(path: &Path) -> Result<LoadedConfig, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let config: AppConfig =
            serde_yaml_ng::from_str(&text).map_err(|source| ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        let warnings = config.validate()?;
        Ok(LoadedConfig { config, warnings })
    }

    /// Enforces the hard invariants of the config and collects non-fatal
    /// warnings.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] for empty ACLs, zero-valued tunables,
    /// duplicate policy names or `match` entries, unknown blocklist
    /// references, and an invalid `log_level`.
    pub fn validate(&self) -> Result<Vec<String>, ConfigError> {
        let mut warnings = Vec::new();

        if self.server.allowed_clients.is_empty() {
            return Err(ConfigError::EmptyField {
                field: "server.allowed_clients".to_owned(),
            });
        }
        for (field, value) in [
            ("server.port", u64::from(self.server.port)),
            ("server.upstream_port", u64::from(self.server.upstream_port)),
            ("server.timeout_ms", self.server.timeout_ms),
            ("server.max_inflight", self.server.max_inflight as u64),
            (
                "server.max_upstream_inflight",
                self.server.max_upstream_inflight as u64,
            ),
            ("server.shutdown_grace_ms", self.server.shutdown_grace_ms),
            (
                "server.tcp_idle_timeout_ms",
                self.server.tcp_idle_timeout_ms,
            ),
            (
                "server.tcp_max_connections",
                self.server.tcp_max_connections as u64,
            ),
            (
                "server.tcp_max_queries_per_conn",
                u64::from(self.server.tcp_max_queries_per_conn),
            ),
            (
                "server.sinkhole_ttl_secs",
                u64::from(self.server.sinkhole_ttl_secs),
            ),
        ] {
            if value == 0 {
                return Err(ConfigError::NonZero { field });
            }
        }

        self.validate_blocklists()?;
        self.validate_policies()?;
        self.validate_storage()?;
        self.validate_log_level()?;

        if self.policies.is_empty() {
            warnings
                .push("no policies configured; default_policy applies to every client".to_owned());
        }
        let outside_action = match self.server.acl_action {
            AclAction::Refuse => "REFUSED",
            AclAction::Drop => "dropped",
        };
        for policy in &self.policies {
            for net in &policy.matches {
                if !self
                    .server
                    .allowed_clients
                    .iter()
                    .any(|allowed| allowed.contains(net))
                {
                    warnings.push(format!(
                        "policy `{}` match {net} lies outside server.allowed_clients; queries from that range are {outside_action}",
                        policy.name
                    ));
                }
            }
        }
        if self.default_policy.blocklists.is_empty() {
            warnings.push(
                "default_policy.blocklists is empty; clients that match no policy are never blocked"
                    .to_owned(),
            );
        }
        if !self.server.listen.is_loopback() {
            if let Some(open) = self
                .server
                .allowed_clients
                .iter()
                .find(|net| net.prefix_len() == 0)
            {
                warnings.push(format!(
                    "server.listen {} is not loopback while allowed_clients includes {open}: this exposes an open resolver",
                    self.server.listen
                ));
            }
        }

        Ok(warnings)
    }

    /// Checks `blocklists.lists`: non-blank names/sources, cache-safe name
    /// pattern, unique names, fetch tunables, and that every policy (and the
    /// default policy) only references lists that exist.
    fn validate_blocklists(&self) -> Result<(), ConfigError> {
        if self.blocklists.fetch_timeout_secs == 0 {
            return Err(ConfigError::NonZero {
                field: "blocklists.fetch_timeout_secs",
            });
        }
        if self.blocklists.max_fetch_bytes == 0 {
            return Err(ConfigError::NonZero {
                field: "blocklists.max_fetch_bytes",
            });
        }
        if !(1..=100).contains(&self.blocklists.min_retained_percent) {
            return Err(ConfigError::OutOfRange {
                field: "blocklists.min_retained_percent",
                value: self.blocklists.min_retained_percent,
                min: 1,
                max: 100,
            });
        }

        let mut names: HashSet<&str> = HashSet::new();
        for (index, list) in self.blocklists.lists.iter().enumerate() {
            if list.name.trim().is_empty() {
                return Err(ConfigError::EmptyField {
                    field: format!("blocklists.lists[{index}].name"),
                });
            }
            // Cache filenames are derived from the name, so restrict it to a
            // traversal-safe, case-stable pattern. (Same rule is enforced
            // again when the cache path is built.)
            if !is_cache_safe_name(&list.name) {
                return Err(ConfigError::InvalidBlocklistName {
                    name: list.name.clone(),
                });
            }
            if list.source.trim().is_empty() {
                return Err(ConfigError::EmptyField {
                    field: format!("blocklists.lists[{index}].source"),
                });
            }
            if !names.insert(list.name.as_str()) {
                return Err(ConfigError::DuplicateBlocklist {
                    name: list.name.clone(),
                });
            }
        }

        let check_refs = |policy: &str, refs: &[String]| -> Result<(), ConfigError> {
            for referenced in refs {
                if !names.contains(referenced.as_str()) {
                    return Err(ConfigError::UnknownBlocklist {
                        policy: policy.to_owned(),
                        list: referenced.clone(),
                    });
                }
            }
            Ok(())
        };

        for policy in &self.policies {
            check_refs(&policy.name, &policy.blocklists)?;
        }
        check_refs("default_policy", &self.default_policy.blocklists)
    }

    /// Checks policy names, duplicate `match` entries (across or within
    /// policies), and blank allow/deny entries.
    fn validate_policies(&self) -> Result<(), ConfigError> {
        let mut policy_names: HashSet<&str> = HashSet::new();
        let mut match_owner: HashMap<IpNet, &str> = HashMap::new();

        for policy in &self.policies {
            if !policy_names.insert(policy.name.as_str()) {
                return Err(ConfigError::DuplicatePolicy {
                    name: policy.name.clone(),
                });
            }
            for net in &policy.matches {
                if let Some(first) = match_owner.insert(*net, policy.name.as_str()) {
                    return Err(ConfigError::DuplicateMatch {
                        net: *net,
                        first: first.to_owned(),
                        second: policy.name.clone(),
                    });
                }
            }
            for (index, entry) in policy.allowlist.iter().enumerate() {
                if entry.trim().is_empty() {
                    return Err(ConfigError::EmptyField {
                        field: format!("policies[{}].allowlist[{index}]", policy.name),
                    });
                }
            }
            for entry in &policy.denylist {
                if entry.trim().is_empty() {
                    return Err(ConfigError::EmptyField {
                        field: format!("policies[{}].denylist", policy.name),
                    });
                }
            }
        }
        Ok(())
    }

    /// Checks the storage tunables that must be strictly positive.
    fn validate_storage(&self) -> Result<(), ConfigError> {
        for (field, value) in [
            ("storage.busy_timeout_ms", self.storage.busy_timeout_ms),
            ("storage.queue_capacity", self.storage.queue_capacity as u64),
            ("storage.flush_rows", self.storage.flush_rows as u64),
            ("storage.flush_interval_ms", self.storage.flush_interval_ms),
            (
                "storage.prune_interval_secs",
                self.storage.prune_interval_secs,
            ),
        ] {
            if value == 0 {
                return Err(ConfigError::NonZero { field });
            }
        }
        Ok(())
    }

    /// Validates `log_level` as a `tracing`/`env-filter` directive.
    fn validate_log_level(&self) -> Result<(), ConfigError> {
        if self.log_level.trim().is_empty() {
            return Err(ConfigError::EmptyField {
                field: "log_level".to_owned(),
            });
        }
        tracing_subscriber::EnvFilter::try_new(&self.log_level)
            .map_err(|source| ConfigError::InvalidLogLevel {
                value: self.log_level.clone(),
                message: source.to_string(),
            })
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_action_default_is_refuse() {
        assert_eq!(AclAction::default(), AclAction::Refuse);
    }

    #[test]
    fn server_defaults_are_the_documented_ones() {
        let server = ServerConfig::default();
        assert_eq!(server.listen, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(server.port, 5353);
        assert!(server.allowed_clients.is_empty());
        assert_eq!(server.upstream, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(server.upstream_port, 53);
        assert_eq!(server.timeout_ms, 2000);
        assert_eq!(server.max_inflight, 1024);
        assert_eq!(server.max_upstream_inflight, 256);
        assert_eq!(server.shutdown_grace_ms, 2000);
        assert_eq!(server.sinkhole_ttl_secs, 60);
        assert_eq!(server.upstream, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn storage_defaults() {
        let storage = StorageConfig::default();
        assert_eq!(storage.db_path, PathBuf::from("voidgate.db"));
        assert!(storage.log_queries);
        assert_eq!(storage.retention_days, 30);
        assert_eq!(storage.busy_timeout_ms, 5000);
        assert_eq!(storage.queue_capacity, 8192);
        assert_eq!(storage.flush_rows, 256);
        assert_eq!(storage.flush_interval_ms, 500);
        assert_eq!(storage.prune_interval_secs, 3600);
    }

    #[test]
    fn client_allowed_uses_cidr_membership() {
        let server = ServerConfig {
            allowed_clients: vec!["192.168.1.0/24".parse::<IpNet>().unwrap()],
            ..ServerConfig::default()
        };
        assert!(server.client_allowed(&"192.168.1.50".parse::<IpAddr>().unwrap()));
        assert!(!server.client_allowed(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!server.client_allowed(&"::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn ipv6_loopback_allowed_by_ipv6_cidr() {
        let server = ServerConfig {
            allowed_clients: vec!["::1/128".parse::<IpNet>().unwrap()],
            ..ServerConfig::default()
        };
        assert!(server.client_allowed(&"::1".parse::<IpAddr>().unwrap()));
    }
}
