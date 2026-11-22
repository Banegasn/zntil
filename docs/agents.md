# Agent setup with zntilctl

`zntilctl` is the optional Rust management client. The gateway server remains
`zntil`. The management client is feature-gated; the server image builds the server
alone and does not run an additional management process.

## Install

```sh
cargo install --git https://github.com/Banegasn/zntil --locked --features cli --bin zntilctl
zntilctl --help
```

Or from a checkout: `cargo build --release --features cli --locked`.

## Authenticate through the web

```sh
zntilctl --gateway https://zntil.tivq.link auth login --name "My setup agent" --no-browser
```

The CLI prints a URL and short verification code to stderr. Open the URL, sign in
to the existing console, compare the code with your terminal, and approve the
requested permission under **CLI access**. Approve only a sign-in you started.
Omit `--no-browser` to attempt opening your local browser automatically.

Default access is **write across the whole gateway**, including redirecting
traffic and editing security rules. Use `--read-only` for monitoring agents.
The CLI never receives the master admin key. It receives a separate 30-day
credential once approval succeeds. The device code expires after ten minutes
and is consumed once; it is never placed in a browser URL.

The credential is saved at `$XDG_CONFIG_HOME/zntil/credentials.json`, falling back
to `$HOME/.config/zntil/credentials.json`, with mode 0600 on Unix. Set
`ZNTIL_CREDENTIALS_FILE` to choose a different file. Keep it out of source control.
The gateway stores only hashes and metadata in `/data/credentials.json`.
Credentials survive server restarts; revocation and master-key rotation invalidate
them. Pending sign-ins and browser sessions do not survive restarts.

```sh
zntilctl auth status
zntilctl auth logout
```

Logout revokes this CLI credential before removing the local login. If the server
is unreachable, logout fails; revoke it later through the console. The console
lists authorized CLIs and can revoke any of them immediately. CLI credentials
cannot approve other clients or administer other credentials, even with write
access. A copied credential has the same permissions until revoked or expired.

For noninteractive jobs, inject an already approved credential through
`ZNTIL_TOKEN` and set `ZNTIL_GATEWAY`. Never pass secrets as command-line
arguments. Saved credentials are bound to their original gateway; selecting
another URL does not send the saved token to that host. HTTPS is required except
for loopback development origins. Redirects are not followed.

## Outputs and failures

Command results are JSON on stdout, with runtime errors as JSON on stderr and
nonzero exit codes. Help and argument-usage messages use standard CLI formatting. Sign-in instructions go to stderr, never the token itself. Use
`--help` on subcommands for their exact flags. Do not scrape the console UI.

## Configure servers, proxies and domains

```sh
zntilctl servers list
zntilctl servers upsert --id web --name "Website origin" \
  --host web.railway.internal --port 3000
zntilctl proxies upsert --id website --server web --domain example.com,www.example.com \
  --upstream-host example.com --rate 20 --burst 100
zntilctl proxies list
```

Use `--tls` for public HTTPS origins (and their actual HTTPS port). The gateway
must be able to reach the selected server. Railway private networking is scoped
to a project/environment; one gateway can serve many domains but does not gain
private access to other projects. Cross-project origins need another reachable,
authenticated connection, usually HTTPS, or consolidation into the same project.

Adding domains changes routing only. DNS records, Railway domain attachment,
certificates and upstream application deployments are separate operations.
Zntil does not receive your Railway/GitHub account credential. Do not repoint live
DNS until the origin route, origin authentication and certificate are ready.
A new proxy has no body-inspection exceptions.

For a complete setup in one atomic change:

```sh
zntilctl config get --output gateway.json
# Edit the servers/proxies arrays; retain the exported revision.
zntilctl config validate --file gateway.json
zntilctl --dry-run config apply --file gateway.json
zntilctl config apply --file gateway.json
```

Use `--file -` for stdin. Configuration bodies are limited to 512 KiB. Every
write carries the expected revision and fails with HTTP 409 if another writer
changed it. On 409, fetch again, reconcile your intended changes with the latest
state, and revalidate. Do not silently overwrite another agent's changes.

`--dry-run` is available for server/proxy/rule edits and config apply; it calls
validation and returns the proposed config without saving or altering traffic.
Rollback is explicit: `zntilctl config rollback --revision 3`. It creates a new
revision from retained history and does not support dry run.

Remove objects with `servers remove --id …`, `proxies remove --id …`, and
`rules remove --proxy … --id …`. A referenced server cannot be removed and at
least one proxy must remain enabled. The server validates all updates atomically.

## Custom domain/path rules

```sh
# Block POSTs under /private on exactly this domain.
zntilctl rules upsert --proxy website --id private-posts --name "Private POSTs" \
  --domain example.com --path /private --method POST --action block

# Separate client budget for exactly /login.
zntilctl rules upsert --proxy website --id login-budget --path /login \
  --match-type exact --action rate-limit --rate 0.5 --burst 5

# Match only a given client network (use the actual trusted client IP).
zntilctl rules upsert --proxy website --id restricted-network --path /admin \
  --cidr 192.0.2.0/24 --action block

zntilctl rules list --proxy website
zntilctl --dry-run rules remove --proxy website --id private-posts
```

Each rule lives in a proxy, with up to 128 rules per proxy. Optional domain,
method and client-CIDR lists are OR within a list and AND between dimensions.
An empty list matches all values for that dimension. Domain lists must be a
subset of the proxy's hostnames. `--method`, `--domain` and `--cidr` accept comma-
separated values or repeated flags. Upsert preserves existing fields unless a
flag changes them; use a full config document to clear an existing match list.

The default path match is **segment prefix**: `/admin` matches `/admin` and
`/admin/users`, not `/administrator`. Trailing slashes on a prefix are ignored;
`/` matches every path. `--match-type exact` matches the whole normalized path.
Request paths are normalized/decoded before matching; query strings are not part
of the path match. Rule paths must already be normalized.

Actions:

- `block`: returns 403 when matched in enforce mode.
- `rate_limit`: an independent per-client token bucket, returning 429 on excess.
  Set both a positive rate and burst of at least one. The bucket is shared by
  the domains/methods/paths matched by that rule within its proxy.

**All matching rules apply in order**; no rule bypasses the built-in filtering,
base rate limits, body limits or origin authentication. In observe mode, matches
are recorded and forwarded; hard resource-capacity limits still apply. Custom
rule client state shares the bounded client-state budget with built-in limiting;
capacity exhaustion returns 503. A rule/policy update may reset its limiter state.

The Activity screen records a matching rejected/observed rule ID, without request
paths or client IPs. The console's proxy editor also exposes the rule array as
validated JSON. Example:

```json
{
  "id": "login-budget",
  "name": "Login client budget",
  "enabled": true,
  "domains": ["example.com"],
  "path": "/login",
  "path_match": "exact",
  "methods": ["POST"],
  "client_cidrs": [],
  "action": "rate_limit",
  "requests_per_second": 0.5,
  "burst": 5
}
```

This version supports block and rate-limit actions, not arbitrary executable
rules, JavaScript challenges, regex expressions or a universal allow/bypass rule.
