# voidgate

[![CI](https://github.com/b5119/voidgate/actions/workflows/ci.yml/badge.svg)](https://github.com/b5119/voidgate/actions/workflows/ci.yml)

**voidgate** is a self-hosted DNS sinkhole ad blocker with per-device and
per-network policies. It answers in a dozen kilobytes of Rust, keeps one
process per host, and stores its query log in a single SQLite file — no web
UI, no phone-home, no external service.

Run it on a Raspberry Pi, a spare box, or your laptop: point a device (or your
whole LAN) at it, give different clients different blocklists and
allow/deny lists, and watch the `voidgate stats` table fill up.

## Features

- **Per-client policies** — assign blocklists, allowlists, and denylists by
  client CIDR (`/32` and `/128` included), resolved by longest-prefix match.
- **Predictable precedence** — `allow > deny > blocklist > forward`, so an
  allowlist entry always wins, no matter how specific a deny rule is.
- **Label-boundary matching** — blocking `ads.com` also blocks `sub.ads.com`
  but never `notads.com`; bare-TLD entries never match.
- **Sinkhole everything** — `A` → `0.0.0.0`, `AAAA` → `::`, all other types
  (including HTTPS/SVCB) → empty `NOERROR`; blocked names are never forwarded.
- **UDP and TCP** on one port, with RFC 1035 framing and client-driven
  `TC`-over-TCP fallback.
- **Blocklist cache** — fetch URL lists (HTTPS) with size and shrink guards,
  reload the cache with `SIGHUP`, and refresh on a timer.
- **Query log** — SQLite via a single writer thread, with retention pruning
  and non-blocking, drop-on-full backpressure.
- **Reporting** — `voidgate stats` prints text tables or JSON.
- **Small and boring** — one binary, one config file, two runtime paths
  (serve / report).

## Architecture

```text
        client (UDP/TCP :53)
              │
              ▼
   ┌───────────────────────┐
   │ server listener       │  UDP + TCP on one port; max_inflight bound;
   └──────────┬────────────┘  TCP connections ACL-checked at accept
              ▼
   ┌───────────────────────┐
   │ handle_query          │  ACL → decode → normalise qname (lowercase,
   └──────────┬────────────┘  strip trailing dot)
              ▼
   ┌───────────────────────┐      blocklists (ArcSwap<BlocklistStore>)
   │ policy::decide        │◄──── SIGHUP reload / refresh timer
   │ allow>deny>blocklist>forward
   └───┬───────────────┬───┘
       │ blocked        │ allowed / forward
       ▼                ▼
  sinkhole          resolver.forward ──► upstream resolver
 0.0.0.0 / ::       (max_upstream_inflight; excess → immediate SERVFAIL)
       │                │
       └───────┬────────┘
               ▼
          reply to client
               │
               ▼
   QueryLog channel ──► writer thread ──► SQLite ──► `voidgate stats`
```

- **config** — YAML parsing, defaults, and validation.
- **blocklists** — hosts/domain parsing, cache, and label-boundary matching.
- **policy** — per-client policies and the allow/deny/blocklist decision.
- **resolver** — forwarding to the upstream resolver over UDP (and TCP on
  `TC`).
- **handler** — the per-query decision pipeline.
- **server** — UDP/TCP listeners and lifecycle (SIGHUP reload, refresh timer).
- **storage** — SQLite query log (single writer thread over an mpsc channel).
- **cli** — `run | update-lists | stats | check-config`.

## Quick start

Requires Rust 1.85+ (SQLite is bundled — no system library needed).

```sh
git clone https://github.com/b5119/voidgate.git
cd voidgate
cargo build --release
```

Write a minimal `config.yaml` (the trimmed example below resolves
`ads.example.com` to `0.0.0.0` on the local machine; see
[Configuration](#configuration) and `config.example.yaml` for everything else):

```yaml
server:
  listen: "127.0.0.1"
  port: 5353
  allowed_clients: ["127.0.0.0/8", "::1/128"]
  upstream: "1.1.1.1"

blocklists:
  lists:
    - name: local-ads
      type: file
      source: "lists/local-ads.txt"

default_policy:
  blocklists: [local-ads]
```

Create the local list and check the config:

```sh
mkdir -p lists
printf 'ads.example.com\ntracker.example.com\n' > lists/local-ads.txt
./target/release/voidgate check-config --config config.yaml
# config OK: config.yaml
```

Fetch any URL lists into the cache (a no-op report for `type: file` lists, but
required before `run` for `type: url` lists):

```sh
./target/release/voidgate update-lists --config config.yaml
# local-ads: local file (read from source at load, not cached)
```

Run the server (it listens on `127.0.0.1:5353` by default):

```sh
./target/release/voidgate run --config config.yaml
```

In another terminal, test it with `dig`:

```sh
dig @127.0.0.1 -p 5353 ads.example.com +short      # 0.0.0.0   (blocked)
dig @127.0.0.1 -p 5353 tracker.example.com +short  # 0.0.0.0   (blocked)
dig @127.0.0.1 -p 5353 example.com +short          # real IP   (forwarded)
```

Then look at what happened:

```sh
./target/release/voidgate stats --config config.yaml
./target/release/voidgate stats --since 1h --top 20 --json --config config.yaml
```

## Configuration

`config.yaml` is validated on load; `voidgate check-config` reports every
problem and warning. Every setting has a default except `server.allowed_clients`
(required, must not be empty) and each blocklist's `name`/`type`/`source`.

### `server`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `listen` | IP address | `127.0.0.1` | Address the UDP/TCP listeners bind to. |
| `port` | port (> 0) | `5353` | DNS port. Use `53` in production (see [permissions](#pointing-a-device-at-voidgate)). |
| `allowed_clients` | list of CIDR | *(required)* | Clients permitted to query. A client outside every range is refused or dropped per `acl_action`. |
| `acl_action` | `refuse` \| `drop` | `refuse` | Reply `REFUSED`, or send nothing at all, for clients outside `allowed_clients`. |
| `upstream` | IP address | `1.1.1.1` | Recursive resolver to forward unmatched names to. |
| `upstream_port` | port (> 0) | `53` | Upstream resolver port. |
| `timeout_ms` | ms (> 0) | `2000` | Per-query upstream timeout. |
| `max_inflight` | count (> 0) | `1024` | Concurrent queries the listener will handle. Packets arriving with no permit are dropped, not queued. |
| `max_upstream_inflight` | count (> 0) | `256` | Concurrent upstream forwards. When full, forward/allowed queries get an immediate `SERVFAIL`; blocked and ACL paths never consume a permit. |
| `shutdown_grace_ms` | ms (> 0) | `2000` | How long to wait for in-flight queries after a shutdown signal. |
| `tcp_enabled` | bool | `true` | Start the TCP listener on the same port as UDP. |
| `tcp_idle_timeout_ms` | ms (> 0) | `2000` | Idle/partial-frame timeout per TCP connection. |
| `tcp_max_connections` | count (> 0) | `128` | Simultaneous TCP connections; extras are closed immediately. |
| `tcp_max_queries_per_conn` | count (> 0) | `100` | Queries served on one TCP connection before it is closed. |
| `sinkhole_ttl_secs` | seconds (> 0) | `60` | TTL attached to sinkhole answers (`0.0.0.0` / `::`). |

### `blocklists`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `cache_dir` | path | `cache` | Where `update-lists` writes fetched lists and the server reads them at startup. |
| `refresh_interval_secs` | seconds | `86400` | How often the running server re-fetches URL lists. `0` disables the timer (`SIGHUP` still reloads the cache). |
| `fetch_timeout_secs` | seconds (> 0) | `30` | HTTP timeout for `update-lists` fetches. |
| `max_fetch_bytes` | bytes (> 0) | `52428800` | Downloads larger than this are rejected and the previous cache file is kept. Default is 50 MiB. |
| `min_retained_percent` | 1..=100 | `10` | A refresh retaining less than this percentage of the previous domain count is rejected (old cache kept). |
| `lists[].name` | `[a-z0-9_-]+` | *(required)* | Unique name, referenced by policies. Becomes the cache filename. |
| `lists[].type` | `url` \| `file` | *(required)* | Fetch over HTTPS, or read a local path. |
| `lists[].source` | string | *(required)* | URL or filesystem path. |

`type: file` lists are read from their source at load and never cached;
`type: url` lists are fetched by `update-lists` (or the refresh timer) into
`<cache_dir>/<name>`.

### `policies` and `default_policy`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `policies[].name` | string | *(required)* | Unique policy name. |
| `policies[].match` | list of CIDR | *(required)* | Client ranges this policy applies to. Overlaps resolve by longest prefix. |
| `policies[].blocklists` | list of names | `[]` | Declared blocklists applied to matching clients. |
| `policies[].allowlist` | list of domains | `[]` | Names (and subdomains) never blocked for these clients. |
| `policies[].denylist` | list of domains | `[]` | Names (and subdomains) always blocked for these clients. |
| `default_policy.blocklists` | list of names | `[]` | Blocklists for clients that match no policy. |
| `default_policy.allowlist` | list of domains | `[]` | Allowlist for unmatched clients. |
| `default_policy.denylist` | list of domains | `[]` | Denylist for unmatched clients. |

### `storage`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `db_path` | path | `voidgate.db` | SQLite query-log path. |
| `log_queries` | bool | `true` | `false` disables logging entirely: no database file, no writer thread. |
| `retention_days` | days | `30` | Rows older than this are pruned at startup and on the prune schedule. `0` keeps rows forever. |
| `busy_timeout_ms` | ms (> 0) | `5000` | SQLite `busy_timeout` for the writer and stats connections. |
| `queue_capacity` | count (> 0) | `8192` | In-memory queue between handlers and the writer. When full, rows are dropped (and counted) instead of blocking DNS. |
| `flush_rows` | count (> 0) | `256` | Commit a transaction once this many rows are pending. |
| `flush_interval_ms` | ms (> 0) | `500` | …or after this long, so low-traffic servers still persist promptly. |
| `prune_interval_secs` | seconds (> 0) | `3600` | How often the writer prunes expired rows. |

### Top level

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `log_level` | tracing filter | `info` | `tracing`/`env-filter` directive, e.g. `debug` or `voidgate=debug`. Logs go to stderr. |

## Policies and precedence

Every query is decided for the client's policy with this precedence:

```text
allowlist  >  denylist  >  blocklist  >  forward
```

1. **Client → policy.** The client IP is matched against every
   `policies[].match` CIDR; the most specific (longest-prefix) match wins.
   A client matching nothing gets `default_policy`. A CIDR cannot appear in two
   policies (config error).
2. **Allow beats deny at any specificity.** Specificity never outranks the
   tier order:

   ```yaml
   policies:
     - name: work
       match: ["192.168.1.20/32"]
       allowlist: ["example.com"]      # wins for example.com and *.example.com
       denylist: ["ads.example.com"]   # never reached for ads.example.com
   ```

   `ads.example.com` is **allowed**, because `allowlist: example.com` covers it
   and `allow` outranks `deny`.
3. **Subdomain matching is label-boundary only.** `ads.com` matches `ads.com`
   and `sub.ads.com`, never `notads.com`. The bare TLD never matches, so a
   poisoned `com` entry cannot block `example.com`.
4. **A blocked name is never forwarded.** Blocked queries get the sinkhole
   address; allowed and unmatched names are forwarded upstream.
5. **`Blocked` names the first list that matched**, in config order, which is
   what the query log records.

Example: give kids' devices a strict list plus a couple of exceptions, and give
the IoT VLAN a lighter one:

```yaml
policies:
  - name: kids
    match: ["192.168.1.50/32", "192.168.1.51/32"]
    blocklists: [stevenblack, social]
    allowlist: ["school.example.com"]
    denylist: ["tiktok.com"]

  - name: iot
    match: ["192.168.1.0/24"]
    blocklists: [stevenblack]

default_policy:
  blocklists: [stevenblack]
```

## Pointing a device at voidgate

The following steps work for a single device (the easiest way to try it).
Router-wide setup is in the next section; treat those steps as **generic
guidance** because router firmware differs.

1. **Bind a reachable address.** On the machine running voidgate, set
   `server.listen` to an address the client can reach (e.g. the LAN IP), and
   keep `allowed_clients` to your own networks:

   ```yaml
   server:
     listen: "192.168.1.10"
     allowed_clients: ["192.168.1.0/24"]
   ```

2. **Point the device at it.** In the device's network settings, set its DNS
   server manually to `192.168.1.10`. (Some devices need a static IP or a
   custom DNS profile to allow this.)

3. **Use port 53 (optional, prettier dig commands).** Ports below 1024 need
   privilege. Either run as root (not recommended) or grant the capability to
   the binary once:

   ```sh
   sudo setcap cap_net_bind_service=+ep ./target/release/voidgate
   ```

   Then set `server.port: 53`.

4. **Don't bind `0.0.0.0` blindly on Linux.** On many distributions
   `systemd-resolved` already listens on `127.0.0.53:53`, so a wildcard bind
   on port 53 fails to start (or conflicts). Bind your specific LAN address,
   or stop/short-circuit the resolved stub listener first. Either way, keep
   `allowed_clients` tight — see [Security and privacy](#security-and-privacy).

## Router-level (generic guidance)

To cover every device on a network, advertise voidgate's address as the DNS
server from your router instead of configuring each device. Exact menus vary:
this is **generic guidance**, not a tested procedure.

- Set the LAN/DHCP DNS option to the voidgate host's LAN IP.
- Or set a static route / port-forward so a fixed address reaches it.
- Keep `allowed_clients` scoped to that LAN; add IPv6 ranges only if you
  actually serve them (see [Limitations](#limitations)).
- Verify from two devices, then check `voidgate stats` to confirm both appear.

## Limitations

DNS sinkholing is a blunt but effective tool. It cannot do everything, and it
is worth knowing where it stops:

- **DoH / DoT bypass it entirely.** Apps and browsers that use DNS-over-HTTPS
  or DNS-over-TLS never send a plain port-53 query, so voidgate never sees
  them. This includes Android **Private DNS**, and the **secure DNS / DoH**
  setting in Firefox and Chrome. Turn those off on devices you want to filter.
- **Hardcoded DNS.** Some apps and devices ignore the system resolver and
  query their own servers directly. Blocking outbound port 53/DoT to force them
  back is a firewall job, not a DNS one.
- **Same-domain and in-app ads cannot be blocked at DNS level.** Ads served
  from the same hostname as the content (or rendered inside a native app's own
  traffic) have no separate name to block. This is why YouTube, Facebook, and
  Twitch ads largely survive DNS blocking.
- **IPv6 router DNS.** A router can advertise an IPv6 DNS server via RDNSS or
  DHCPv6 that clients prefer over your IPv4 setting. If you only configure the
  IPv4 DNS option, devices may silently bypass voidgate. Either configure the
  IPv6 DNS option too, or disable IPv6 DNS advertisement.
- **CDN-shared addresses.** Blocking a name shared with legitimate content can
  over-block; use allowlists for the exceptions you need.

## Security and privacy

- **Open resolver risk.** A DNS server reachable from outside your network is
  an open resolver — it can be abused for amplification. Bind a private
  address, and keep `allowed_clients` as narrow as possible. Validation warns
  when `listen` is not loopback while `allowed_clients` includes `0.0.0.0/0`;
  heed that warning.
- **The query log is a browsing history.** Every allowed/blocked/forwarded
  query is stored, so the database is sensitive. On Unix the file is created
  `0600` (owner-only). Protect the directory too, and:
  - set `storage.retention_days` to bound how long history is kept, or
  - set `storage.log_queries: false` to keep nothing at all (no database file
    is created, and `voidgate stats` will tell you there is nothing to read).
- **No phone-home.** voidgate only talks to the upstream resolver you
  configure and to the URLs you list in `blocklists.lists`.
- **`voidgate stats` is read-only.** It opens the database with
  `SQLITE_OPEN_READ_ONLY` and never creates it.

## CLI reference

```
voidgate [--config <path>] <command>
```

`--config` is global and defaults to `config.yaml`.

| Command | What it does |
| --- | --- |
| `run` | Serve DNS on the configured UDP + TCP port until `Ctrl-C`/`SIGTERM`. |
| `update-lists` | Fetch every `type: url` list into the cache (atomic write); report each list. `type: file` lists are reported but not cached. |
| `stats [--top N] [--since <window>] [--json]` | Report the query log. |
| `check-config` | Load and validate the config, print warnings, touch no sockets or database. |

`stats` flags:

- `--top N` — how many blocked domains to list (default `10`).
- `--since <window>` — only count queries newer than `30s`, `5m`, `1h`, `24h`,
  `7d`, etc.
- `--json` — print the report as JSON instead of text tables.

**Exit codes** (every command): `0` success, `1` configuration/usage error
(including a missing query log or a bad `--since`), `2` runtime error. Errors
are one line plus an actionable `hint:`. `stdout` carries data (reports, tables,
JSON); logs and warnings go to `stderr`.

## systemd

Run voidgate as a dedicated, unprivileged user and grant only the
port-binding capability. Example unit (`/etc/systemd/system/voidgate.service`):

```ini
[Unit]
Description=voidgate DNS sinkhole
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=voidgate
WorkingDirectory=/var/lib/voidgate
ExecStart=/usr/local/bin/voidgate run --config /etc/voidgate/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

`ExecReload` sends `SIGHUP`, which reloads the blocklists from the cache
without restarting the process (run `voidgate update-lists` first to refresh
the cache). `AmbientCapabilities=CAP_NET_BIND_SERVICE` lets the `voidgate` user
bind port 53 without running as root.

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

All three must pass. Integration tests use loopback listeners only and never
touch the real network. See `AGENTS.md` for module notes and conventions.

## Roadmap

- CNAME-cloaking detection (follow CNAME chains to block cloaked trackers).
- Web dashboard over the query log.
- DoH endpoint blocking.
- Docker image.

## License

MIT — see [LICENSE](LICENSE).
