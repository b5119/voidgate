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
//! - IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are canonicalised to IPv4
//!   before matching, on **both** sides: clients passed to
//!   [`PolicyEngine::resolve`] and CIDRs in `match` lists (a mapped CIDR such
//!   as `::ffff:10.0.0.0/104` is rewritten to `10.0.0.0/8`). One form to
//!   reason about, and no address can dodge a rule by being mapped.
//! - Domain matching walks labels on boundaries (`a.b.example` → `b.example`)
//!   and never tests the bare TLD, mirroring [`crate::blocklists::store`]: a
//!   denylist entry `com` cannot deny `example.com`, and an entry `ads.com`
//!   never matches `notads.com`. Everything here is pure and synchronous — no
//!   I/O and no allocation in the label walk.

use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::blocklists::BlocklistStore;
use crate::config::AppConfig;

/// Name reported for the [`AppConfig::default_policy`] fallback.
pub const DEFAULT_POLICY_NAME: &str = "default";

/// What voidgate should do with one query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The allowlist covers the domain: forward upstream, never sinkhole.
    ///
    /// Allow wins over deny even when the deny entry is more specific
    /// (`allow: example.com` + `deny: a.example.com` → `Allowed`).
    Allowed,
    /// The denylist covers the domain: answer with the sinkhole address.
    Denied,
    /// A blocklist covers the domain: answer with the sinkhole address.
    Blocked {
        /// Name of the blocklist that matched, for the query log.
        list: String,
    },
    /// Nothing matched: forward upstream unchanged.
    Forward,
}

/// A resolved policy: blocklist names plus allow/deny domain sets.
///
/// Obtained from [`PolicyEngine::resolve`]; allow/deny entries are normalised
/// (lowercased, `*.` prefix and trailing dots stripped) and stored as sets so
/// matching is allocation-free.
#[derive(Debug, Clone)]
pub struct Policy {
    name: String,
    blocklists: Vec<String>,
    allowlist: HashSet<String>,
    denylist: HashSet<String>,
}

impl Policy {
    /// Assembles a policy, normalising every allow/deny entry.
    fn new(name: &str, blocklists: &[String], allowlist: &[String], denylist: &[String]) -> Self {
        Self {
            name: name.to_owned(),
            blocklists: blocklists.to_vec(),
            allowlist: normalize_entries(allowlist),
            denylist: normalize_entries(denylist),
        }
    }

    /// The policy's name (`"default"` for the fallback policy).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Blocklist names this policy consults, in config order. The first list
    /// that matches a domain is the one named in [`Decision::Blocked`].
    #[must_use]
    pub fn blocklists(&self) -> &[String] {
        &self.blocklists
    }
}

/// One CIDR → policy rule; rules are kept sorted by prefix length.
#[derive(Debug, Clone, Copy)]
struct MatchRule {
    net: IpNet,
    policy: usize,
}

/// Resolved per-client policies with CIDR longest-prefix matching.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policies: Vec<Policy>,
    /// Sorted longest-prefix first, so the first `contains` hit wins.
    rules: Vec<MatchRule>,
    default_policy: Policy,
}

impl PolicyEngine {
    /// Builds the engine from a validated [`AppConfig`].
    ///
    /// Referenced blocklists are guaranteed to exist by
    /// [`AppConfig::validate`], so this cannot fail; an unreferenced or
    /// missing list simply never matches anything.
    #[must_use]
    pub fn from_config(config: &AppConfig) -> Self {
        let mut policies = Vec::with_capacity(config.policies.len());
        let mut rules = Vec::new();
        for policy in &config.policies {
            let index = policies.len();
            policies.push(Policy::new(
                &policy.name,
                &policy.blocklists,
                &policy.allowlist,
                &policy.denylist,
            ));
            rules.extend(policy.matches.iter().map(|net| MatchRule {
                net: canonical_net(*net),
                policy: index,
            }));
        }
        rules.sort_by_key(|rule| std::cmp::Reverse(rule.net.prefix_len()));

        let default_policy = Policy::new(
            DEFAULT_POLICY_NAME,
            &config.default_policy.blocklists,
            &config.default_policy.allowlist,
            &config.default_policy.denylist,
        );
        Self {
            policies,
            rules,
            default_policy,
        }
    }

    /// Resolves `client` to the policy whose CIDR wins by longest prefix.
    ///
    /// Returns [`Self::default_policy`] when nothing matches. IPv4-mapped IPv6
    /// clients are canonicalised to IPv4 first, so `::ffff:10.0.0.1` matches
    /// `10.0.0.0/8` exactly as `10.0.0.1` does.
    #[must_use]
    pub fn resolve(&self, client: IpAddr) -> &Policy {
        let client = canonical_client(client);
        self.rules
            .iter()
            .find(|rule| rule.net.contains(&client))
            .map_or(&self.default_policy, |rule| &self.policies[rule.policy])
    }

    /// The fallback policy used by clients that match no `policies` entry.
    #[must_use]
    pub fn default_policy(&self) -> &Policy {
        &self.default_policy
    }
}

/// Decides what to do with `domain` under `policy`, consulting `blocklists`.
///
/// Precedence is allowlist > denylist > blocklist > forward. `domain` is
/// expected to be normalised (lowercase, no trailing dot) by the caller —
/// [`crate::handler`] does this once at the query boundary — but any input is
/// safe here: junk, empty strings, and unnormalised names simply fail to match
/// instead of panicking.
///
/// # Examples
///
/// ```
/// use voidgate::policy::{decide, Decision, PolicyEngine};
/// use voidgate::config::AppConfig;
/// use voidgate::blocklists::BlocklistStore;
/// use serde_yaml_ng::from_str;
///
/// let config: AppConfig = from_str(
///     "policies:\n  - name: lan\n    match: [\"10.0.0.0/8\"]\n    blocklists: [\"ads\"]\n    allowlist: [\"safe.example\"]\ndefault_policy: {}\n",
/// )
/// .unwrap();
/// let engine = PolicyEngine::from_config(&config);
/// let mut store = BlocklistStore::new();
/// store.insert("ads", ["ads.example"]);
///
/// let policy = engine.resolve("10.0.0.5".parse().unwrap());
/// assert_eq!(decide(policy, "safe.example", &store), Decision::Allowed);
/// assert_eq!(decide(policy, "ads.example", &store), Decision::Blocked { list: "ads".to_owned() });
/// assert_eq!(decide(policy, "unlisted.example", &store), Decision::Forward);
/// ```
#[must_use]
pub fn decide(policy: &Policy, domain: &str, blocklists: &BlocklistStore) -> Decision {
    if domain_matches(&policy.allowlist, domain) {
        return Decision::Allowed;
    }
    if domain_matches(&policy.denylist, domain) {
        return Decision::Denied;
    }
    for list in &policy.blocklists {
        if blocklists.matches(list, domain) {
            return Decision::Blocked { list: list.clone() };
        }
    }
    Decision::Forward
}

/// Canonicalises an IPv4-mapped IPv6 address to its IPv4 form.
fn canonical_client(client: IpAddr) -> IpAddr {
    match client {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// Rewrites a v4-mapped v6 CIDR (`::ffff:a.b.c.d/n`, `n >= 96`) into the
/// equivalent IPv4 CIDR (`a.b.c.d/(n-96)`).
fn canonical_net(net: IpNet) -> IpNet {
    match net {
        IpNet::V6(v6) if v6.prefix_len() >= 96 => match v6.addr().to_ipv4_mapped() {
            // prefix_len - 96 is at most 32, so the IPv4 prefix is always valid.
            Some(ip) => IpNet::new_assert(IpAddr::V4(ip), v6.prefix_len() - 96),
            None => net,
        },
        other => other,
    }
}

/// Normalises a config allow/deny entry: `"*.Example.COM."` → `"example.com"`.
///
/// Returns `None` for entries that normalise to nothing (e.g. `"*."`), which
/// are then dropped rather than matching everything.
fn normalize_domain(entry: &str) -> Option<String> {
    let trimmed = entry.trim();
    let without_wildcard = trimmed.strip_prefix("*.").unwrap_or(trimmed);
    let without_dot = without_wildcard.trim_end_matches('.');
    (!without_dot.is_empty()).then(|| without_dot.to_ascii_lowercase())
}

/// Normalises and de-duplicates a list of allow/deny entries.
fn normalize_entries(entries: &[String]) -> HashSet<String> {
    entries
        .iter()
        .filter_map(|entry| normalize_domain(entry))
        .collect()
}

/// Does `domain` (or one of its parent domains) appear in `entries`?
///
/// Candidates are built by walking label boundaries from the front and stop
/// before the bare TLD, so `ads.com` matches `sub.ads.com` but not
/// `notads.com`, and a `com` entry matches nothing. Slices the domain
/// in place: no allocation, no `ends_with`.
fn domain_matches(entries: &HashSet<String>, domain: &str) -> bool {
    if entries.is_empty() || domain.is_empty() {
        return false;
    }
    let Some(last_dot) = domain.rfind('.') else {
        // A single label is a bare TLD or unresolvable junk: never match.
        return false;
    };

    let mut start = 0;
    loop {
        if start <= last_dot && entries.contains(&domain[start..]) {
            return true;
        }
        match domain[start..].find('.') {
            Some(offset) => start += offset + 1,
            None => return false,
        }
    }
}
