//! The per-query decision pipeline: one decoded packet in, one response out.
//!
//! Steps (M5a):
//! 1. enforce `server.allowed_clients` → `REFUSED` (or silence for
//!    `acl_action: drop`),
//! 2. resolve the client's policy (CIDR longest prefix),
//! 3. decide **allowlist > denylist > blocklist > forward**,
//! 4. synthesise sinkhole answers for blocked names — `A` → `0.0.0.0`,
//!    `AAAA` → `::`, **every other qtype (including HTTPS/SVCB, type 65) →
//!    NOERROR with an empty answer**; blocked names are never forwarded,
//! 5. log the action (`allowed` | `blocked` | `forwarded` | `servfail`) with
//!    upstream latency.
//!
//! Malformed packets are dropped; upstream failures become SERVFAIL. Neither
//! path may panic.
