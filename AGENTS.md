# voidgate — agent & contributor notes

DNS sinkhole ad blocker with per-device/per-network policies. Rust, single
crate (`src/lib.rs` + `src/main.rs`), tokio + hickory-proto + rusqlite.

## Build and gates

Every milestone must pass all three gates before committing:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Commit messages follow `M<n>: <topic>` (one milestone per commit). Work one
milestone at a time and stop for review after each.

## Conventions

- `unwrap_used` and `expect_used` are denied by `[lints.clippy]`; tests opt out
  with a crate-level `#![allow(clippy::unwrap_used, clippy::expect_used)]`.
- `missing_docs` is warned; every public item needs a doc comment.
- No hardcoded tunables: timeouts, caps, TTLs, and intervals live in
  `config.yaml` (see `config.example.yaml`).
- Integration tests never touch the real network: loopback listeners only.
- Config validation (`AppConfig::validate`) is the only place refs/names are
  checked; later modules may assume a validated `AppConfig`.

## Query decision rules (M3)

Client resolution (`PolicyEngine::resolve`) then domain decision
(`policy::decide`) follow these rules, in order:

1. **Client → policy**: CIDR longest-prefix match, `/32` and `/128` included.
   Equal-length ties cannot occur because duplicate `match` entries are a
   config error. A client matching nothing gets `default_policy`.
2. **Precedence**: `allow > deny > blocklist > forward`, per client policy.
3. **Allow beats deny at any specificity**: `allow: example.com` +
   `deny: a.example.com` → `Allowed` for `a.example.com`. Specificity never
   outranks the tier order.
4. **Subdomain matching is label-boundary only** (no `ends_with`): an entry
   `ads.com` matches `ads.com` and `sub.ads.com`, but never `notads.com`.
   The same walk applies to blocklist entries, allow entries, and deny entries.
5. **The bare TLD never matches**: a candidate is only tested if a label
   remains after it, so an entry `com` matches nothing, and a single-label
   query (`localhost`) never matches. A poisoned `com` entry cannot block
   `example.com`.
6. **IPv4-mapped IPv6 is canonicalised on both sides**: clients like
   `::ffff:10.0.0.1` are matched as `10.0.0.1`, and a mapped CIDR is rewritten
   (`::ffff:10.0.0.0/104` → `10.0.0.0/8`), so no client dodges a rule by using
   the mapped form, and only one spelling of an address needs a rule.
7. **Domain normalisation happens once, at the handler boundary** (lowercase,
   strip trailing dot). `decide` assumes normalised input: it never panics on
   anything else, but uppercase or dotted input simply fails to match the
   allow/deny sets. Note the blocklist store itself is case-insensitive, so
   unnormalised input can still hit a blocklist — pass normalised names.
8. **Allow/deny entries are normalised at load**: lowercased, leading `*.`
   stripped, trailing dots stripped, blanks dropped. `"*.Example.COM."` and
   `example.com` behave identically.
9. **`Blocked { list }` names the first list that matched**, in policy/config
   order — stable for the query log.
10. **An empty or malformed domain never matches**: it falls through to
    `Forward` rather than panicking.
11. **Policies may only reference declared blocklists**; a reference to an
    undeclared list is rejected by config validation
    (`ConfigError::UnknownBlocklist`), so the engine can never consult a
    missing list.
