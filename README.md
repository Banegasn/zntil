# Zntil

**Your edge. Your rules.**

Zntil (pronounced “zentil”) is a small, self-hosted Rust reverse proxy that routes
traffic, filters common attacks and puts explicit limits in front of your apps.
It includes an authenticated management console in the same binary.

[Website](https://zntil.tivq.link/) · [Console sign-in](https://zntil.tivq.link/console/) · [License](LICENSE)

The hosted console manages its owner's gateway; it is not a public demo or a
shared proxy service. Deploy your own instance to manage your applications.

> Early implementation. Zntil is not an audited, comprehensive WAF or a global
> DDoS absorption network. It does not promise protection from every attack.
> Browser challenges and advanced botnet identification are not implemented.

## How it fits

```text
Internet → hosting edge / HTTPS / optional CDN → Zntil → application origins
                                                   ├─ website
                                                   ├─ API
                                                   └─ another service
```

A domain selects an explicitly configured proxy and upstream. Unknown domains
receive 421; Zntil is not an open proxy. Keep origins private where possible, or
require an origin token on public upstreams to prevent direct bypass.

## Features

- HTTP hostname routing to multiple services, optional verified upstream HTTPS,
  HTTP keepalive, streamed responses and WebSocket upgrades.
- Per-proxy global and per-client token buckets, plus separate budgets for
  sensitive paths and verified crawlers.
- Connection admission, bounded concurrent HTTP sessions, a header deadline,
  body-size limits and bounded shared memory for body inspection.
- Known probe detection, decaying suspicion scores and temporary bans.
- SQL injection and XSS pattern detection through pinned, vendored libinjection.
  Decoded queries and supported JSON/form/text bodies are inspected.
- Explicit body-inspection exceptions for arbitrary content and signed webhooks.
  Their resource limits still apply; application authorization and signatures
  remain the application's responsibility.
- Googlebot/Bingbot IP-feed verification tooling. A claimed user-agent alone is
  insufficient, and verified crawlers still have rate and security limits.
- Built-in server/proxy/domain editors, draft validation, atomic hot application,
  optimistic revision checks and rollback to retained configurations.
- Persistent configuration and up to 20 previous revisions in a local file.
  No Redis, database, Node runtime or external frontend dependencies at runtime.

## Quick start

Requires Rust supporting edition 2024, a C compiler, CMake, pkg-config and OpenSSL
headers. The Dockerfile uses Rust 1.96. On Debian:

```sh
sudo apt-get install build-essential cmake pkg-config libssl-dev
cargo build --release --locked
cargo run --release -- --check
```

Start a test origin, then run Zntil in another terminal:

```sh
python3 -m http.server 9000
```

```sh
ZNTIL_CONFIG=config/local.toml ./target/release/zntil
curl -H 'Host: app.test' http://127.0.0.1:8080/
curl -i -H 'Host: app.test' http://127.0.0.1:8080/.git/config
```

The sample maps `localhost` and `app.test` to port 9000, and `api.test` to port
9001. On macOS, set `OPENSSL_DIR` if OpenSSL is not detected automatically.

## Console and public home page

To enable management, configure these fields before the first start:

```toml
admin_host = "gateway.example.com"
admin_token_env = "ZNTIL_ADMIN_TOKEN"
admin_data_dir = "/data"
```

Set `ZNTIL_ADMIN_TOKEN` to a randomly generated secret of at least 32 characters.
Never put its value in source control, URLs, logs or frontend configuration.
The hostname serves:

| Path | Purpose |
| --- | --- |
| `/` | Public Zntil introduction |
| `/console/` | Console sign-in and dashboard |
| `/_zntil/admin/…` | Authenticated management API |
| `/_zntil/console/…` | Embedded console assets |

Management is served only for `admin_host`; other application domains do not
expose it. For local development, omitting `admin_host` allows console paths on
any host; Railway management requires a dedicated hostname and HTTPS. Omitting
both `admin_token_env` and `admin_data_dir` disables management.

Login exchanges the key for a one-hour HttpOnly, SameSite=Strict cookie, with
Secure on HTTPS. The key is not saved in browser storage. Sessions live in
memory and expire on restart. Rotating the environment secret and restarting
revokes access. Anyone holding the key can redirect traffic and change policy.

Server and proxy edits are drafts until **Apply changes**. Validation and saving
require the current revision; competing edits return 409. Files are written and
synced before an atomic rename and routing swap. Failed persistence does not
change live routing. Requests already in flight keep their original upstream.
At least one proxy must remain enabled; referenced servers cannot be removed.
New proxies start with no body-inspection exceptions.

The startup TOML seeds an empty management store. Once present,
`<admin_data_dir>/control.json` owns saved routes and takes precedence over the
TOML's routes. It contains hostnames and secret environment-variable names, never
their values. Use one replica per store: concurrent writers and multi-replica
configuration coordination are not implemented. Back up the persistent volume.

## Railway deployment

1. Use the Dockerfile and customize `config/railway.toml` with your admin domain,
   application domains, private origin hostname and actual application port.
2. Set `ZNTIL_CONFIG=/app/config/railway.toml`, `PORT=8080` and
   `ZNTIL_ADMIN_TOKEN` on the gateway service.
3. Mount a persistent volume at `/data`. The entrypoint initializes ownership of
   this directory and runs the application as UID 10001.
4. Configure a health check at `/_zntil/health`. Expose each custom domain on
   port 8080 and add the DNS records Railway supplies.
5. Ensure the gateway can reach its origins. Railway private networking is scoped
   to the project/environment; cross-project origins need another reachable,
   authenticated connection, typically HTTPS.

Registering a routing hostname in the console does **not** register the domain,
change DNS, create a Railway domain attachment or issue a certificate. Those
steps stay with your hosting/DNS provider. No Railway account token is required
by or exposed to the console. CDN settings and purges also remain at the hosting
edge; Zntil has no built-in response cache. Hosting and bandwidth costs apply.

TLS can also terminate in Zntil using `tls_cert`, `tls_key` and `tls_listen`, or
at a trusted reverse proxy. Never expose a plain HTTP origin and assume its
private hostname alone is authentication.

## Limits and enforcement

These are **generic defaults**; every installation can override them:

| Limit | Default | Configuration |
| --- | --- | --- |
| Client requests per proxy | 10/s, burst 100 | Route; console |
| Total requests per proxy | 200/s, burst 400 | Route; console |
| Sensitive paths per client | 0.5/s, burst 10 | Route; management API |
| Verified crawler requests | 5/s, burst 30 | Route; management API |
| Upstream read timeout | 60 s | Route; console |
| Active requests / HTTP sessions | 256 / 512 | Startup TOML |
| New downstream connections | 50/s, burst 100 | Startup TOML |
| Header deadline | 10 s | Startup TOML |
| Headers / request URI | 16 KiB / 8 KiB | Startup TOML |
| Request / inspected body | 2 MiB / 2 MiB | Startup TOML |
| Shared body inspection buffer | 16 MiB | Startup TOML |
| Client tracking entries | 16,384, sharded and bounded | Startup TOML |
| Temporary ban | 60 s | Startup TOML |

Token buckets allow short bursts and refill continuously. Budgets are per process
and proxy, not synchronized across replicas. Clients behind one public IP share
its client budget. Exceeding a client rate normally returns 429; global overload
or exhausted capacity returns 503; oversized bodies return 413. Some malformed or
interrupted requests fail at the HTTP framework or transport layer.

`mode = "enforce"` rejects policy matches. `observe` forwards behavioral/WAF
matches while counting them, but still enforces structural validation, body,
connection and resource limits. It is not a bypass for overload protection.

Inspected bodies are buffered before their body bytes are sent upstream. Headers
may already have reached the origin, so applications must handle interrupted
requests. Unsupported/opaque body formats and configured exceptions stream
without these SQLi/XSS body checks. Upload body callbacks enforce a 60-second
elapsed limit; downstream read and write timeouts are 15 and 30 seconds. Upgraded
WebSockets are bounded by session counts and I/O timeouts, not HTTP body limits.
The proxy does not replay requests automatically after upstream failure.

Global settings and enforcement mode require a restart/redeployment. The console
edits per-proxy rates, domains, server settings, sensitive-path prefixes, body
exceptions and upstream timeout. Additional serialized route fields can be
changed through the authenticated API.

## Client identity, crawlers and origin protection

By default the socket peer is the client. Forwarded headers are accepted only
from configured `trusted_proxies`, or through `trust_railway_edge = true` on a
Railway deployment. Do not enable Railway trust on arbitrary public ingress.
Forwarded identity and hop-by-hop headers are sanitized before proxying.

Use `ingress_token_env` when another trusted edge must authenticate to Zntil,
and `origin_token_env` on a route/server when the origin validates a shared
header. These legacy header names remain `X-Rustgate-Ingress-Token` and
`X-Rustgate-Origin-Token` for compatibility with existing origins. Secrets are
read from the named environment variable. Enforce the token at the origin too.

The `scripts/` feed updater builds a Google/Bing IP-range file. Set `crawler_file`
to its path and keep feeds fresh. Missing or expired feeds do not grant verified
crawler status. User-agent strings alone never establish crawler identity.

## Observability and privacy

The console holds process counters, recent traffic-minute buckets and up to 200
sampled activity events in memory. One in twenty ordinary completed requests is
sampled, together with exceptional decisions. Events include time, hostname,
method, status, reason and duration; they omit raw client IPs, user agents, URLs,
query strings, bodies, cookies and credentials. Console polling is excluded.
Restart resets telemetry. CDN cache hits bypass this process and are absent.

Responses carry `X-Protection: active` when generated/processed by Zntil's hooks.
Some framework-level errors may omit it. Headers injected by an outer hosting
edge cannot be removed from inside Zntil. This marker is informational; it is not
proof that a request received every possible security check.

`diagnostics_token_env` optionally protects the legacy aggregate diagnostics
endpoint at `/_rustgate/diagnostics` via `X-Rustgate-Diagnostics-Token`. Keep the
key private. `RUSTGATE_CONFIG`, old `/_rustgate/console/` links on the management
host and `/_rustgate/health` remain compatibility aliases during the rename.
The current console uses `/_zntil/admin/` and its own cookie path.

## Management API

Prefix: `/_zntil/admin/`. JSON responses are private/no-store. Authenticate with
the session cookie or `Authorization: Bearer <admin key>`. Mutations also require
an exact same-origin `Origin` header; arbitrary CORS access is not enabled.

| Method | Endpoint | JSON body |
| --- | --- | --- |
| POST | `/login` | `{ "token": "…" }` |
| GET | `/state` | — |
| POST | `/validate` | `{ "revision": 1, "servers": […], "proxies": […] }` |
| PUT | `/config` | Same as validation |
| POST | `/rollback` | `{ "revision": 1, "current_revision": 2 }` |
| POST | `/logout` | `{}` |

See the serialized state and `src/control.rs` / `src/config.rs` for field schemas.
Limits include 64 servers, 64 proxies, 512 active hostnames, a 512 KiB update body
and bounded login attempts/sessions. The console does not expose secret values.

## Development and checks

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release --locked
python3 tests/integration.py
python3 tests/management.py
node --test tests/console.test.cjs
```

Python tests start real local HTTP origins and a compiled proxy, covering
HTTP/TLS routing, uploads, WebSockets, identity sanitation, filtering, resource
limits, authentication, CSRF, live reconfiguration, revision conflicts,
persistence, rollback and in-flight route isolation. Node is needed only for the
UI regression tests. `ZNTIL_BINARY` can override the test binary path.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Vendored libinjection uses
its upstream BSD license; its revision and source checksums are recorded in
`vendor/libinjection/UPSTREAM.json`. Other dependencies retain their licenses.
