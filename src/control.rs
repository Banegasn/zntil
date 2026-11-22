use crate::{
    config::{Config, Route, hostname, secret},
    guard::Bucket,
};
use arc_swap::ArcSwap;
use blake2::{Blake2s256, Digest};
use bytes::Bytes;
use pingora::{http::ResponseHeader, prelude::*, proxy::Session};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

const MAX_CONFIG_BYTES: usize = 512 * 1024;
const MAX_HISTORY: usize = 20;
const SESSION_SECONDS: u64 = 3600;
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub origin_token_env: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    pub id: String,
    pub name: String,
    pub server_id: String,
    pub enabled: bool,
    pub route: Route,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Desired {
    pub revision: u64,
    pub servers: Vec<Server>,
    pub proxies: Vec<Proxy>,
}
#[derive(Clone, Deserialize, Serialize)]
struct Snapshot {
    revision: u64,
    created_at: u64,
    summary: String,
    servers: Vec<Server>,
    proxies: Vec<Proxy>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Store {
    current: Snapshot,
    history: Vec<Snapshot>,
}

pub struct RuntimeRule {
    pub rule: crate::rules::Rule,
    pub key: usize,
    pub rate_route: Option<Route>,
}
pub struct Entry {
    pub rules: Vec<RuntimeRule>,
    pub key: usize,
    pub id: String,
    pub route: Route,
    pub global: Mutex<Bucket>,
    pub dns: tokio::sync::Mutex<Option<(SocketAddr, Instant)>>,
    pub origin_token: Option<String>,
}
pub struct Routing {
    pub hosts: HashMap<String, Arc<Entry>>,
    pub entries: Vec<Arc<Entry>>,
}

#[derive(Clone, Serialize)]
pub struct Event {
    pub time: u64,
    pub host: String,
    pub method: String,
    pub status: u16,
    pub outcome: &'static str,
    pub reason: &'static str,
    pub rule_id: Option<String>,
    pub latency_ms: u64,
}
#[derive(Clone, Serialize)]
struct Minute {
    minute: u64,
    requests: u64,
    blocked: u64,
    observed: u64,
    errors: u64,
}
#[derive(Default)]
struct Activity {
    events: VecDeque<Event>,
    traffic: VecDeque<Minute>,
    completed: u64,
}
struct Auth {
    key: String,
    sessions: Mutex<HashMap<[u8; 32], Instant>>,
    attempts: Mutex<HashMap<IpAddr, (Bucket, Instant)>>,
}
pub struct Control {
    pub routing: ArcSwap<Routing>,
    base: Config,
    store: Mutex<Store>,
    next_key: AtomicUsize,
    auth: Option<Auth>,
    devices: Option<Arc<crate::device::DeviceAuth>>,
    file: Option<PathBuf>,
    activity: Mutex<Activity>,
}
#[derive(Debug)]
pub struct ApiError(pub u16, pub String);
fn bad(message: impl Into<String>) -> ApiError {
    ApiError(400, message.into())
}
fn internal() -> ApiError {
    ApiError(
        500,
        "Could not persist configuration; no change was applied.".into(),
    )
}

impl Control {
    pub fn new(base: &Config) -> std::result::Result<Arc<Self>, Box<dyn std::error::Error>> {
        let admin = secret(&base.admin_token_env)?;
        let file = base
            .admin_data_dir
            .as_ref()
            .map(|p| PathBuf::from(p).join("control.json"));
        let store = if let Some(path) = &file
            && path.exists()
        {
            let raw = fs::read(path)?;
            if raw.len() > 16 * 1024 * 1024 {
                return Err("management store is too large".into());
            }
            let s: Store = serde_json::from_slice(&raw)?;
            if s.history.len() > MAX_HISTORY {
                return Err("management history exceeds its bound".into());
            }
            s
        } else {
            let servers = base
                .routes
                .iter()
                .enumerate()
                .map(|(i, r)| Server {
                    id: format!("server-{}", i + 1),
                    name: r.upstream.clone(),
                    host: r.upstream.clone(),
                    port: r.upstream_port,
                    tls: r.upstream_tls,
                    origin_token_env: r.origin_token_env.clone(),
                })
                .collect();
            let proxies = base
                .routes
                .iter()
                .enumerate()
                .map(|(i, r)| Proxy {
                    id: format!("proxy-{}", i + 1),
                    name: r.hosts[0].clone(),
                    server_id: format!("server-{}", i + 1),
                    enabled: true,
                    route: r.clone(),
                })
                .collect();
            Store {
                current: Snapshot {
                    revision: 1,
                    created_at: now(),
                    summary: "Imported startup configuration".into(),
                    servers,
                    proxies,
                },
                history: vec![],
            }
        };
        let control = Arc::new(Self {
            routing: ArcSwap::from_pointee(Routing {
                hosts: HashMap::new(),
                entries: vec![],
            }),
            base: base.clone(),
            store: Mutex::new(store),
            next_key: AtomicUsize::new(1),
            devices: admin
                .as_ref()
                .map(|key| {
                    crate::device::DeviceAuth::new(base.admin_data_dir.as_deref().unwrap(), key)
                        .map(Arc::new)
                })
                .transpose()?,
            auth: admin.map(|key| Auth {
                key,
                sessions: Mutex::new(HashMap::new()),
                attempts: Mutex::new(HashMap::new()),
            }),
            file,
            activity: Mutex::new(Activity::default()),
        });
        {
            let s = control.store.lock().unwrap();
            let routing = control
                .compile(&s.current.servers, &s.current.proxies)
                .map_err(|e| e.1)?;
            control.persist(&s).map_err(|e| e.1)?;
            control.routing.store(Arc::new(routing));
        }
        Ok(control)
    }

    fn compile(
        &self,
        servers: &[Server],
        proxies: &[Proxy],
    ) -> std::result::Result<Routing, ApiError> {
        if servers.is_empty() || servers.len() > 64 || proxies.is_empty() || proxies.len() > 64 {
            return Err(bad("Keep between 1 and 64 servers and proxies."));
        }
        let mut server_map = HashMap::new();
        for s in servers {
            if !valid_id(&s.id)
                || s.name.trim().is_empty()
                || s.name.len() > 120
                || hostname(&s.host).as_deref() != Some(s.host.as_str())
                || s.port == 0
                || s.origin_token_env.as_ref().is_some_and(|v| {
                    v.is_empty()
                        || v.len() > 120
                        || !v
                            .bytes()
                            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                })
                || server_map.insert(s.id.as_str(), s).is_some()
            {
                return Err(bad(
                    "Server names, IDs, hostnames, ports or token variable names are invalid or duplicated.",
                ));
            }
        }
        let mut ids = HashSet::new();
        let mut routes = vec![];
        let public_hosts: HashSet<&str> = proxies
            .iter()
            .flat_map(|p| p.route.hosts.iter().map(String::as_str))
            .collect();
        if servers.iter().any(|s| {
            public_hosts.contains(s.host.as_str())
                || self.base.admin_host.as_ref() == Some(&s.host)
                || s.host
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| !destination_allowed(ip, self.base.trust_railway_edge))
        }) {
            return Err(bad(
                "An upstream cannot point back to a gateway hostname or to a local metadata address.",
            ));
        }
        for p in proxies {
            if !valid_id(&p.id)
                || p.name.trim().is_empty()
                || p.name.len() > 120
                || !ids.insert(&p.id)
            {
                return Err(bad("Proxy names and IDs must be valid and unique."));
            }
            let server = server_map
                .get(p.server_id.as_str())
                .ok_or_else(|| bad("A proxy references a missing server."))?;
            let mut route = p.route.clone();
            route.upstream = server.host.clone();
            route.upstream_port = server.port;
            route.upstream_tls = server.tls;
            route.origin_token_env = server.origin_token_env.clone();
            if route.hosts.is_empty()
                || route.hosts.len() > 64
                || route.hosts.iter().any(|h| h.len() > 253)
                || route.deny_prefixes.len() > 64
                || route.sensitive_prefixes.len() > 64
                || route.body_inspection_exempt_prefixes.len() > 64
            {
                return Err(bad(
                    "Each proxy needs 1–64 domains; each path policy is limited to 64 entries.",
                ));
            }
            // Validate disabled proxies too; duplicate domains are only forbidden among active proxies.
            let mut one = self.base.clone();
            one.routes = vec![route.clone()];
            one.validate().map_err(|e| bad(e.to_string()))?;
            secret(&route.origin_token_env)
                .map_err(|_| bad("The origin token environment variable is missing or invalid."))?;
            if p.enabled {
                routes.push((p.id.clone(), route));
            }
        }
        if routes.is_empty() {
            return Err(bad("Keep at least one proxy enabled."));
        }
        if routes.iter().map(|(_, r)| r.hosts.len()).sum::<usize>() > 512 {
            return Err(bad("At most 512 active domains are supported."));
        }
        let mut all = self.base.clone();
        all.routes = routes.iter().map(|(_, r)| r.clone()).collect();
        all.validate().map_err(|e| bad(e.to_string()))?;
        let previous = self.routing.load_full();
        let mut hosts = HashMap::new();
        let mut entries = vec![];
        for (id, route) in routes {
            let entry = if let Some(old) = previous
                .entries
                .iter()
                .find(|old| old.id == id && old.route == route)
            {
                old.clone()
            } else {
                Arc::new(Entry {
                    key: self.next_key.fetch_add(1, Ordering::Relaxed),
                    id,
                    global: Mutex::new(Bucket::new(route.global_burst, Instant::now())),
                    dns: tokio::sync::Mutex::new(None),
                    origin_token: secret(&route.origin_token_env)
                        .map_err(|_| bad("Invalid origin token variable."))?,
                    rules: route
                        .rules
                        .iter()
                        .filter(|r| r.enabled)
                        .map(|r| {
                            let rate_route = if r.action == crate::rules::Action::RateLimit {
                                let mut policy = route.clone();
                                policy.rules = Vec::new();
                                policy.requests_per_second = r.requests_per_second.unwrap();
                                policy.burst = r.burst.unwrap();
                                Some(policy)
                            } else {
                                None
                            };
                            RuntimeRule {
                                rule: r.clone(),
                                key: self.next_key.fetch_add(1, Ordering::Relaxed),
                                rate_route,
                            }
                        })
                        .collect(),
                    route,
                })
            };
            for host in &entry.route.hosts {
                hosts.insert(host.clone(), entry.clone());
            }
            entries.push(entry);
        }
        Ok(Routing { hosts, entries })
    }

    fn persist(&self, store: &Store) -> std::result::Result<(), ApiError> {
        let Some(path) = &self.file else {
            return Ok(());
        };
        let dir = path.parent().ok_or_else(internal)?;
        fs::create_dir_all(dir).map_err(|_| internal())?;
        let temporary = dir.join(".control.json.tmp");
        let raw = serde_json::to_vec(store).map_err(|_| internal())?;
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut out = opts.open(&temporary).map_err(|_| internal())?;
        out.write_all(&raw)
            .and_then(|_| out.sync_all())
            .map_err(|_| internal())?;
        fs::rename(&temporary, path).map_err(|_| internal())?;
        // The rename is the commit point. A directory sync failure must not report an unapplied update.
        if let Ok(dir) = fs::File::open(dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    pub fn apply(&self, desired: Desired) -> std::result::Result<(), ApiError> {
        let mut stored = self.store.lock().unwrap();
        if desired.revision != stored.current.revision {
            return Err(ApiError(
                409,
                "Configuration changed in another session. Reload before applying your draft."
                    .into(),
            ));
        }
        let routing = self.compile(&desired.servers, &desired.proxies)?;
        let mut next = stored.clone();
        next.history.push(next.current.clone());
        if next.history.len() > MAX_HISTORY {
            next.history.remove(0);
        }
        next.current = Snapshot {
            revision: desired.revision.checked_add(1).ok_or_else(internal)?,
            created_at: now(),
            summary: format!(
                "Saved {} servers and {} proxies",
                desired.servers.len(),
                desired.proxies.len()
            ),
            servers: desired.servers,
            proxies: desired.proxies,
        };
        self.persist(&next)?;
        self.routing.store(Arc::new(routing));
        *stored = next;
        Ok(())
    }

    pub fn rollback(&self, target: u64, expected: u64) -> std::result::Result<(), ApiError> {
        let desired = {
            let store = self.store.lock().unwrap();
            if expected != store.current.revision {
                return Err(ApiError(
                    409,
                    "Configuration changed. Reload before rolling back.".into(),
                ));
            }
            let snapshot = store
                .history
                .iter()
                .find(|s| s.revision == target)
                .ok_or_else(|| bad("Revision is no longer in retained history."))?;
            Desired {
                revision: expected,
                servers: snapshot.servers.clone(),
                proxies: snapshot.proxies.clone(),
            }
        };
        self.apply(desired)
    }

    pub fn record(&self, event: Event) {
        let mut a = self.activity.lock().unwrap();
        a.completed = a.completed.saturating_add(1);
        let minute = event.time / 60 * 60;
        if a.traffic.back().is_none_or(|b| b.minute != minute) {
            a.traffic.push_back(Minute {
                minute,
                requests: 0,
                blocked: 0,
                observed: 0,
                errors: 0,
            });
        }
        while a.traffic.len() > 60 {
            a.traffic.pop_front();
        }
        if let Some(b) = a.traffic.back_mut() {
            b.requests += 1;
            b.blocked += u64::from(event.outcome == "blocked");
            b.observed += u64::from(event.outcome == "observed");
            b.errors += u64::from(event.outcome == "error");
        }
        // All exceptional decisions, plus one in twenty ordinary requests. Never raw paths/IPs.
        if event.outcome != "allowed" || a.completed.is_multiple_of(20) {
            a.events.push_front(event);
            if a.events.len() > 200 {
                a.events.pop_back();
            }
        }
    }

    pub fn state(&self, counters: Value, uptime: u64) -> Value {
        let s = self.store.lock().unwrap();
        let a = self.activity.lock().unwrap();
        let history = s
            .history
            .iter()
            .chain(std::iter::once(&s.current))
            .rev()
            .map(|r| json!({"revision":r.revision,"created_at":r.created_at,"summary":r.summary}))
            .collect::<Vec<_>>();
        json!({"revision":s.current.revision,"persisted":self.file.is_some(),"mode":self.base.mode,"uptime_seconds":uptime,
            "counters":counters,"traffic":a.traffic,"events":a.events,"servers":s.current.servers,"proxies":s.current.proxies,"history":history,
            "platform":{"provider":if self.base.trust_railway_edge {"railway"} else {"standalone"},"automatic_domains":false},
            "warnings":["CDN cache hits do not reach this gateway and are not included in traffic counts.","Routing changes apply immediately. A new public hostname also needs DNS and a Railway domain/HTTPS attachment.","Activity is in memory since restart; configuration and the last 20 revisions persist."]})
    }

    pub fn is_control_path(path: &str) -> bool {
        path == "/console"
            || path.starts_with("/console/")
            || path == "/_zntil/console"
            || path.starts_with("/_zntil/console/")
            || path.starts_with("/_zntil/admin/")
            || path == "/_rustgate/console"
            || path.starts_with("/_rustgate/console/")
            || path.starts_with("/_rustgate/admin/")
    }

    pub fn is_control_request(&self, session: &Session) -> bool {
        Self::is_control_path(session.req_header().uri.path())
            || self.base.admin_host.as_ref().is_some_and(|expected| {
                session
                    .req_header()
                    .headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .and_then(hostname)
                    .as_ref()
                    == Some(expected)
            })
    }

    pub async fn handle(
        self: &Arc<Self>,
        session: &mut Session,
        counters: Value,
        uptime: u64,
    ) -> Result<bool> {
        if self.auth.is_none() {
            return send(
                session,
                404,
                "application/json",
                b"{\"error\":\"Not found.\"}",
                None,
            )
            .await;
        }
        let host = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok());
        if self
            .base
            .admin_host
            .as_ref()
            .is_some_and(|expected| host.and_then(hostname).as_ref() != Some(expected))
        {
            return send(
                session,
                404,
                "application/json",
                b"{\"error\":\"Not found.\"}",
                None,
            )
            .await;
        }
        if self.base.trust_railway_edge && !secure_session(session, &self.base) {
            return json_response(
                session,
                400,
                json!({"error":"Use HTTPS for the management console."}),
                None,
            )
            .await;
        }
        let path = session
            .req_header()
            .uri
            .path()
            .replacen("/_rustgate/", "/_zntil/", 1);
        let method = session.req_header().method.clone();
        if method == http::Method::GET {
            match path.as_str() {
                "/" => {
                    return send(
                        session,
                        200,
                        "text/html; charset=utf-8",
                        include_bytes!("../console/home.html"),
                        None,
                    )
                    .await;
                }
                "/home.css" => {
                    return send(
                        session,
                        200,
                        "text/css; charset=utf-8",
                        include_bytes!("../console/home.css"),
                        None,
                    )
                    .await;
                }
                "/console" | "/console/" => {
                    return send(
                        session,
                        200,
                        "text/html; charset=utf-8",
                        include_bytes!("../console/index.html"),
                        None,
                    )
                    .await;
                }

                "/_zntil/console" | "/_zntil/console/" => {
                    return send(
                        session,
                        200,
                        "text/html; charset=utf-8",
                        include_bytes!("../console/index.html"),
                        None,
                    )
                    .await;
                }
                "/_zntil/console/app.js" => {
                    return send(
                        session,
                        200,
                        "application/javascript; charset=utf-8",
                        include_bytes!("../console/app.js"),
                        None,
                    )
                    .await;
                }
                "/_zntil/console/styles.css" => {
                    return send(
                        session,
                        200,
                        "text/css; charset=utf-8",
                        include_bytes!("../console/styles.css"),
                        None,
                    )
                    .await;
                }
                _ => {}
            }
        }
        if !path.starts_with("/_zntil/admin/") {
            return json_response(session, 404, json!({"error":"Not found."}), None).await;
        }
        if !matches!(method.as_str(), "GET" | "POST" | "PUT") {
            return json_response(session, 405, json!({"error":"Method not allowed."}), None).await;
        }
        if method != http::Method::GET && !same_origin(session) {
            return json_response(
                session,
                403,
                json!({"error":"A same-origin request is required."}),
                None,
            )
            .await;
        }
        let auth = self.auth.as_ref().unwrap();
        if path == "/_zntil/admin/device/start" && method == http::Method::POST {
            let peer = session
                .client_addr()
                .and_then(|a| a.as_inet())
                .map(|a| a.ip());
            let ip =
                peer.and_then(|p| crate::client_ip(p, &session.req_header().headers, &self.base));
            if ip.is_none_or(|ip| !login_attempt(auth, ip)) {
                return api_error(
                    session,
                    ApiError(429, "Too many CLI sign-in attempts.".into()),
                )
                .await;
            }
            let value = match read_json(session, 4096).await {
                Ok(v) => v,
                Err(e) => return api_error(session, e).await,
            };
            let origin = session
                .req_header()
                .headers
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            return match self.devices.as_ref().unwrap().start(
                value
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("Zntil CLI"),
                value.get("write").and_then(Value::as_bool).unwrap_or(false),
                origin,
            ) {
                Ok(v) => json_response(session, 200, v, None).await,
                Err(e) => api_error(session, e).await,
            };
        }
        if path == "/_zntil/admin/device/poll" && method == http::Method::POST {
            let value = match read_json(session, 4096).await {
                Ok(v) => v,
                Err(e) => return api_error(session, e).await,
            };
            let code = value
                .get("device_code")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let devices = self.devices.as_ref().unwrap().clone();
            return match tokio::task::spawn_blocking(move || devices.poll(&code)).await {
                Ok(Ok((status, v))) => json_response(session, status, v, None).await,
                Ok(Err(e)) => api_error(session, e).await,
                Err(_) => api_error(session, internal()).await,
            };
        }
        if path == "/_zntil/admin/login" && method == http::Method::POST {
            let peer = session
                .client_addr()
                .and_then(|a| a.as_inet())
                .map(|a| a.ip());
            let ip =
                peer.and_then(|p| crate::client_ip(p, &session.req_header().headers, &self.base));
            if ip.is_none_or(|ip| !login_attempt(auth, ip)) {
                return json_response(
                    session,
                    429,
                    json!({"error":"Too many sign-in attempts. Wait one minute."}),
                    None,
                )
                .await;
            }
            let value = match read_json(session, 4096).await {
                Ok(v) => v,
                Err(e) => return api_error(session, e).await,
            };
            let candidate = value.get("token").and_then(Value::as_str).unwrap_or("");
            if candidate.len() > 256 || !bool::from(candidate.as_bytes().ct_eq(auth.key.as_bytes()))
            {
                return json_response(
                    session,
                    401,
                    json!({"error":"Invalid admin access key."}),
                    None,
                )
                .await;
            }
            let mut raw = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut raw);
            let token = raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let accepted = {
                let mut sessions = auth.sessions.lock().unwrap();
                sessions.retain(|_, expiry| *expiry > Instant::now());
                if sessions.len() >= 32 {
                    false
                } else {
                    sessions.insert(
                        hash(&token),
                        Instant::now() + Duration::from_secs(SESSION_SECONDS),
                    );
                    true
                }
            };
            if !accepted {
                return json_response(
                    session,
                    503,
                    json!({"error":"Too many active admin sessions."}),
                    None,
                )
                .await;
            }
            let secure = secure_session(session, &self.base);
            let cookie = format!(
                "gateway_session={token}; HttpOnly; SameSite=Strict; Path=/_zntil/admin; Max-Age={SESSION_SECONDS}{}",
                if secure { "; Secure" } else { "" }
            );
            return json_response(session, 200, json!({"authenticated":true}), Some(&cookie)).await;
        }
        let browser_admin = authorized(auth, session);
        let cli_token = session
            .req_header()
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(str::to_owned);
        let cli_access = cli_token
            .as_deref()
            .and_then(|t| self.devices.as_ref().unwrap().access(t));
        if !browser_admin && cli_access.is_none() {
            return json_response(
                session,
                401,
                json!({"error":"Sign in to the management console."}),
                None,
            )
            .await;
        }
        if path == "/_zntil/admin/tokens/revoke-self" && method == http::Method::POST {
            let devices = self.devices.as_ref().unwrap().clone();
            let token = cli_token.unwrap_or_default();
            return match tokio::task::spawn_blocking(move || devices.revoke_self(&token)).await {
                Ok(Ok(v)) => json_response(session, 200, v, None).await,
                Ok(Err(e)) => api_error(session, e).await,
                Err(_) => api_error(session, internal()).await,
            };
        }
        if path == "/_zntil/admin/devices"
            || path == "/_zntil/admin/device/approve"
            || path.starts_with("/_zntil/admin/tokens")
        {
            if !browser_admin {
                return api_error(
                    session,
                    ApiError(
                        403,
                        "Only a console administrator can approve or revoke other CLI credentials."
                            .into(),
                    ),
                )
                .await;
            }
            let devices = self.devices.as_ref().unwrap().clone();
            if method == http::Method::GET && path == "/_zntil/admin/devices" {
                return json_response(session, 200, devices.pending(), None).await;
            }
            if method == http::Method::GET && path == "/_zntil/admin/tokens" {
                return json_response(session, 200, devices.list(), None).await;
            }
            let value = match read_json(session, 4096).await {
                Ok(v) => v,
                Err(e) => return api_error(session, e).await,
            };
            if path == "/_zntil/admin/device/approve" && method == http::Method::POST {
                return match devices.approve(
                    value.get("user_code").and_then(Value::as_str).unwrap_or(""),
                    value
                        .get("approve")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                ) {
                    Ok(v) => json_response(session, 200, v, None).await,
                    Err(e) => api_error(session, e).await,
                };
            }
            if path == "/_zntil/admin/tokens/revoke" && method == http::Method::POST {
                let id = value
                    .get("token_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                return match tokio::task::spawn_blocking(move || devices.revoke(&id)).await {
                    Ok(Ok(v)) => json_response(session, 200, v, None).await,
                    Ok(Err(e)) => api_error(session, e).await,
                    Err(_) => api_error(session, internal()).await,
                };
            }
            return api_error(session, ApiError(404, "Not found.".into())).await;
        }
        if !browser_admin
            && cli_access == Some(false)
            && method != http::Method::GET
            && path != "/_zntil/admin/validate"
        {
            return api_error(
                session,
                ApiError(403, "This CLI credential is read-only.".into()),
            )
            .await;
        }
        if path == "/_zntil/admin/logout" && method == http::Method::POST {
            if let Some(token) = cookie_token(session) {
                auth.sessions.lock().unwrap().remove(&hash(&token));
            }
            return send(session,204,"application/json",b"",Some("gateway_session=; HttpOnly; SameSite=Strict; Path=/_zntil/admin; Max-Age=0; Secure")).await;
        }
        if path == "/_zntil/admin/state" && method == http::Method::GET {
            return json_response(session, 200, self.state(counters, uptime), None).await;
        }
        let value = match read_json(session, MAX_CONFIG_BYTES).await {
            Ok(v) => v,
            Err(e) => return api_error(session, e).await,
        };
        if path == "/_zntil/admin/validate" && method == http::Method::POST {
            let desired = match serde_json::from_value::<Desired>(value) {
                Ok(v) => v,
                Err(_) => return api_error(session, bad("Invalid configuration document.")).await,
            };
            return match self.compile(&desired.servers, &desired.proxies) {
                Ok(_) => json_response(session, 200, json!({"valid":true}), None).await,
                Err(e) => api_error(session, e).await,
            };
        }
        let owned = self.clone();
        let result = if path == "/_zntil/admin/config" && method == http::Method::PUT {
            let desired = match serde_json::from_value::<Desired>(value) {
                Ok(v) => v,
                Err(_) => return api_error(session, bad("Invalid configuration document.")).await,
            };
            tokio::task::spawn_blocking(move || owned.apply(desired)).await
        } else if path == "/_zntil/admin/rollback" && method == http::Method::POST {
            let (Some(revision), Some(expected)) = (
                value.get("revision").and_then(Value::as_u64),
                value.get("current_revision").and_then(Value::as_u64),
            ) else {
                return api_error(session, bad("A target and current revision are required."))
                    .await;
            };
            tokio::task::spawn_blocking(move || owned.rollback(revision, expected)).await
        } else {
            return json_response(session, 404, json!({"error":"Not found."}), None).await;
        };
        match result {
            Ok(Ok(())) => json_response(session, 200, self.state(counters, uptime), None).await,
            Ok(Err(e)) => api_error(session, e).await,
            Err(_) => api_error(session, internal()).await,
        }
    }
}

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
pub fn destination_allowed(ip: IpAddr, railway: bool) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_unspecified()
                || v.is_multicast()
                || v.is_link_local()
                || v.is_broadcast()
                || railway && v.is_loopback())
        }
        IpAddr::V6(v) => {
            !(v.is_unspecified()
                || v.is_multicast()
                || v.is_unicast_link_local()
                || railway && v.is_loopback())
        }
    }
}

fn hash(s: &str) -> [u8; 32] {
    Blake2s256::digest(s.as_bytes()).into()
}
fn cookie_token(session: &Session) -> Option<String> {
    let mut result = None;
    for value in session.req_header().headers.get_all("cookie").iter() {
        for entry in value.to_str().ok()?.split(';') {
            if let Some(v) = entry.trim().strip_prefix("gateway_session=") {
                if result.is_some() || v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return None;
                }
                result = Some(v.to_owned());
            }
        }
    }
    result
}
fn authorized(auth: &Auth, session: &Session) -> bool {
    if let Some(key) = session
        .req_header()
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        && bool::from(key.as_bytes().ct_eq(auth.key.as_bytes()))
    {
        return true;
    }
    let Some(token) = cookie_token(session) else {
        return false;
    };
    auth.sessions
        .lock()
        .unwrap()
        .get(&hash(&token))
        .is_some_and(|expiry| *expiry > Instant::now())
}
fn login_attempt(auth: &Auth, ip: IpAddr) -> bool {
    let mut attempts = auth.attempts.lock().unwrap();
    let now = Instant::now();
    attempts.retain(|_, (_, seen)| now.duration_since(*seen) < Duration::from_secs(120));
    if !attempts.contains_key(&ip) && attempts.len() >= 512 {
        return false;
    }
    let (bucket, seen) = attempts
        .entry(ip)
        .or_insert_with(|| (Bucket::new(5.0, now), now));
    *seen = now;
    bucket.take(1.0 / 12.0, 5.0, now)
}
fn same_origin(session: &Session) -> bool {
    let req = session.req_header();
    if req.headers.get_all("origin").iter().count() != 1 {
        return false;
    }
    let Some(origin) = req
        .headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<http::Uri>().ok())
    else {
        return false;
    };
    matches!(origin.scheme_str(), Some("http" | "https"))
        && origin.authority().map(|a| a.as_str())
            == req.headers.get("host").and_then(|v| v.to_str().ok())
        && origin.path_and_query().is_none_or(|p| p.as_str() == "/")
}
fn secure_session(session: &Session, base: &Config) -> bool {
    session.digest().is_some_and(|d| d.ssl_digest.is_some())
        || (base.trust_railway_edge
            && session
                .req_header()
                .headers
                .get("x-forwarded-proto")
                .is_some_and(|v| v == "https"))
}
async fn read_json(session: &mut Session, max: usize) -> std::result::Result<Value, ApiError> {
    let req = session.req_header();
    if req
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v.split(';').next().unwrap_or("").trim() != "application/json")
    {
        return Err(ApiError(415, "Send application/json.".into()));
    }
    if req
        .headers
        .get("content-encoding")
        .is_some_and(|v| v != "identity")
    {
        return Err(ApiError(
            415,
            "Compressed management requests are not supported.".into(),
        ));
    }
    if req
        .headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > max)
    {
        return Err(ApiError(413, "Management request is too large.".into()));
    }
    let mut data = vec![];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let chunk = tokio::time::timeout(left, session.read_request_body())
            .await
            .map_err(|_| ApiError(408, "Request timed out.".into()))?
            .map_err(|_| bad("Could not read management request."))?;
        let Some(chunk) = chunk else {
            break;
        };
        if data.len().saturating_add(chunk.len()) > max {
            return Err(ApiError(413, "Management request is too large.".into()));
        }
        data.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&data).map_err(|_| bad("Invalid JSON."))
}
async fn api_error(session: &mut Session, e: ApiError) -> Result<bool> {
    json_response(session, e.0, json!({"error":e.1}), None).await
}
async fn json_response(
    session: &mut Session,
    status: u16,
    value: Value,
    cookie: Option<&str>,
) -> Result<bool> {
    send(
        session,
        status,
        "application/json; charset=utf-8",
        &serde_json::to_vec(&value).unwrap(),
        cookie,
    )
    .await
}
async fn send(
    session: &mut Session,
    status: u16,
    mime: &str,
    body: &[u8],
    cookie: Option<&str>,
) -> Result<bool> {
    let mut h = ResponseHeader::build(status, Some(10))?;
    h.insert_header("content-type", mime)?;
    h.insert_header("content-length", body.len().to_string())?;
    h.insert_header("cache-control", "private, no-store")?;
    h.insert_header("x-protection", "active")?;
    h.insert_header("x-content-type-options", "nosniff")?;
    h.insert_header("referrer-policy", "no-referrer")?;
    h.insert_header("x-frame-options", "DENY")?;
    h.insert_header("strict-transport-security", "max-age=31536000")?;
    h.insert_header("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")?;
    if let Some(cookie) = cookie {
        h.insert_header("set-cookie", cookie)?;
    }
    session.set_keepalive(None);
    session
        .write_response_header(Box::new(h), body.is_empty())
        .await?;
    if !body.is_empty() {
        session
            .write_response_body(Some(Bytes::copy_from_slice(body)), true)
            .await?;
    }
    Ok(true)
}
