//! Typed errors produced while loading and validating configuration.

use std::path::PathBuf;

use ipnet::IpNet;
use thiserror::Error;

/// Every way a `config.yaml` file can fail to become a usable [`AppConfig`](super::AppConfig).
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The config file could not be read from disk.
    #[error("failed to read config file `{path}`: {source}")]
    Read {
        /// Path that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// The file was read but is not valid configuration YAML.
    #[error("failed to parse config file `{path}`: {source}")]
    Parse {
        /// Path that failed to parse.
        path: PathBuf,
        /// Underlying YAML/serde error.
        source: serde_yaml_ng::Error,
    },

    /// A required list or string field is missing content.
    #[error("`{field}` must not be empty")]
    EmptyField {
        /// Dotted path of the offending field (e.g. `server.allowed_clients`).
        field: String,
    },

    /// A numeric field must be strictly positive.
    #[error("`{field}` must be greater than 0")]
    NonZero {
        /// Dotted path of the offending field.
        field: &'static str,
    },

    /// The same CIDR appears in the `match` list of two policies (or twice in
    /// one policy), so client resolution would be ambiguous.
    #[error("duplicate match entry {net} shared by policies `{first}` and `{second}`")]
    DuplicateMatch {
        /// The duplicated CIDR.
        net: IpNet,
        /// Name of the policy that claimed it first.
        first: String,
        /// Name of the policy that claimed it second.
        second: String,
    },

    /// Two policies share a name.
    #[error("duplicate policy name `{name}`")]
    DuplicatePolicy {
        /// The repeated policy name.
        name: String,
    },

    /// Two blocklists share a name, so policy references would be ambiguous.
    #[error("duplicate blocklist name `{name}`")]
    DuplicateBlocklist {
        /// The repeated blocklist name.
        name: String,
    },

    /// A policy (or the default policy) references a blocklist that is not
    /// declared in `blocklists.lists`.
    #[error("policy `{policy}` references unknown blocklist `{list}`")]
    UnknownBlocklist {
        /// Name of the referencing policy (`default_policy` for the fallback).
        policy: String,
        /// The undeclared blocklist name.
        list: String,
    },

    /// `log_level` is not a valid `tracing` filter directive.
    #[error("invalid `log_level` `{value}`: {message}")]
    InvalidLogLevel {
        /// The rejected value.
        value: String,
        /// Parser message explaining the rejection.
        message: String,
    },
}
