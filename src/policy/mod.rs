//! Per-client policy resolution and domain decisions.
//!
//! Rules:
//! - Clients are matched to a [`PolicyConfig`](crate::config::PolicyConfig)
//!   by CIDR **longest prefix** (there is no exact-IP special case; a `/32` or
//!   `/128` entry simply wins by prefix length). Unmatched clients use
//!   `default_policy`.
//! - A decision for a domain follows **allowlist > denylist > blocklist >
//!   forward**; allowlist and denylist entries match the domain *and all of
//!   its subdomains*.
//!
//! TODO(M3): implement `PolicyEngine::resolve` and `decide`.

pub mod error;
