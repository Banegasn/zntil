mod config;
mod control;
mod crawlers;
mod guard;
mod waf;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use config::{Config, Mode, hostname, secret};
use crawlers::Crawlers;
use guard::{Bucket, Decision, Guard, normalized_path, path_matches, suspicious};
use pingora::{
    http::{RequestHeader, ResponseHeader},
    prelude::*,
    proxy::{ProxyHttp, Session},
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    blocked: AtomicU64,
    observed: AtomicU64,
    crawlers: AtomicU64,
    errors: AtomicU64,
}
#[derive(Debug)]
struct Admission {
    bucket: Mutex<Bucket>,
    rate: f64,
    burst: f64,
}
#[async_trait]
impl pingora::listeners::ConnectionFilter for Admission {
    async fn should_accept(&self, _addr: Option<&SocketAddr>) -> bool {
        self.bucket
            .lock()
            .unwrap()
            .take(self.rate, self.burst, Instant::now())
    }
}
// Bound HTTP sessions before reading their headers; unfinished headers count too.
struct Transport {
    app: Arc<pingora::proxy::HttpProxy<Gateway>>,
    slots: tokio::sync::Semaphore,
    header_timeout: Duration,
}
#[async_trait]
impl pingora::apps::HttpServerApp for Transport {
    async fn process_new_http(
        self: &Arc<Self>,
        mut session: pingora::protocols::http::ServerSession,
        shutdown: &pingora::server::ShutdownWatch,
    ) -> Option<pingora::apps::ReusedHttpStream> {
        let _permit = self.slots.try_acquire().ok()?;
        session.set_read_timeout(Some(self.header_timeout));
        if session.is_http2() {
            return self.app.process_new_http(session, shutdown).await;
        }
        // The framework initially applies a 60s keepalive deadline. Track header
        // completion separately so slow-drip headers cannot reset our absolute deadline.
        let parsed = Arc::new(AtomicBool::new(false));
        session.set_connection_user_context(Some(Box::new(parsed.clone())));
        let pending = self.app.process_new_http(session, shutdown);
        tokio::pin!(pending);
        match tokio::time::timeout(self.header_timeout, &mut pending).await {
            Ok(result) => result,
            Err(_) if parsed.load(Ordering::Acquire) => pending.await,
            Err(_) => None,
        }
    }
    async fn http_cleanup(&self) {
        self.app.http_cleanup().await;
    }
}
struct Gateway {
    config: Config,
    control: Arc<control::Control>,
    guard: Guard,
    crawlers: Crawlers,
    active: Arc<AtomicUsize>,
    buffered: Arc<AtomicUsize>,
    counters: Counters,
    ingress_token: Option<String>,
    diagnostics_token: Option<String>,
    last_report: AtomicU64,
    started: Instant,
}
struct Ctx {
    route: Option<Arc<control::Entry>>,
    host: String,
    ip: Option<IpAddr>,
    scheme: &'static str,
    active: Option<Arc<AtomicUsize>>,
    body_bytes: usize,
    tunnel: bool,
    started: Instant,
    body_kind: waf::BodyKind,
    buffer: BytesMut,
    reserved: usize,
    budget: Option<Arc<AtomicUsize>>,
    control_plane: bool,
    blocked: bool,
    observed: bool,
    reason: &'static str,
}
impl Default for Ctx {
    fn default() -> Self {
        Self {
            route: None,
            host: String::new(),
            ip: None,
            scheme: "http",
            active: None,
            body_bytes: 0,
            tunnel: false,
            started: Instant::now(),
            body_kind: waf::BodyKind::Opaque,
            buffer: BytesMut::new(),
            reserved: 0,
            budget: None,
            control_plane: false,
            blocked: false,
            observed: false,
            reason: "passed",
        }
    }
}
impl Drop for Ctx {
    fn drop(&mut self) {
        if let Some(a) = self.active.take() {
            a.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(a) = self.budget.take() {
            a.fetch_sub(self.reserved, Ordering::Relaxed);
        }
    }
}

fn authenticate(actual: Option<&http::HeaderValue>, expected: &Option<String>) -> bool {
    expected.as_ref().is_none_or(|secret| {
        actual.is_some_and(|v| bool::from(v.as_bytes().ct_eq(secret.as_bytes())))
    })
}

fn client_ip(peer: IpAddr, headers: &http::HeaderMap, config: &Config) -> Option<IpAddr> {
    let peer = match peer {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(peer),
        _ => peer,
    };
    if config.trust_railway_edge || config.trusted_proxies.iter().any(|n| n.contains(&peer)) {
        // One authoritative header only. Never select an untrusted X-Forwarded-For element.
        let value = headers.get("x-real-ip")?.to_str().ok()?;
        if headers.get_all("x-real-ip").iter().count() != 1 {
            return None;
        }
        let ip: IpAddr = value.parse().ok()?;
        Some(match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        })
    } else {
        Some(peer)
    }
}

impl Gateway {
    fn new(config: Config) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        if config.trust_railway_edge && std::env::var("RAILWAY_PROJECT_ID").is_err() {
            return Err(
                "trust_railway_edge requires a Railway runtime; never enable it on a public VPS"
                    .into(),
            );
        }
        let control = control::Control::new(&config)?;
        Ok(Self {
            control,
            guard: Guard::new(config.max_clients),
            crawlers: Crawlers::load(config.crawler_file.as_deref())?,
            active: Arc::new(AtomicUsize::new(0)),
            buffered: Arc::new(AtomicUsize::new(0)),
            counters: Counters::default(),
            ingress_token: secret(&config.ingress_token_env)?,
            diagnostics_token: secret(&config.diagnostics_token_env)?,
            last_report: AtomicU64::new(0),
            started: Instant::now(),
            config,
        })
    }
    async fn reject(&self, session: &mut Session, status: u16, ctx: &mut Ctx) -> Result<bool> {
        ctx.blocked = true;
        if ctx.reason == "passed" {
            ctx.reason = match status {
                421 => "unknown_host",
                429 => "rate_limit",
                503 => "resource_limit",
                413 => "body_size_limit",
                403 => "policy_block",
                _ => "invalid_request",
            };
        }
        self.counters.blocked.fetch_add(1, Ordering::Relaxed);
        session.set_keepalive(None);
        let mut h = ResponseHeader::build(status, Some(4))?;
        h.insert_header("x-protection", "active")?;
        h.insert_header("content-length", "0")?;
        h.insert_header("cache-control", "no-store")?;
        if status == 429 || status == 503 {
            h.insert_header("retry-after", "5")?;
        }
        session.write_response_header(Box::new(h), true).await?;
        Ok(true)
    }
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = Ctx;
    fn new_ctx(&self) -> Ctx {
        Ctx::default()
    }
    fn on_connection_reuse(
        &self,
        _session: &mut Session,
        _ctx: &mut Ctx,
        previous: Box<dyn std::any::Any + Send + Sync>,
    ) {
        if let Ok(parsed) = previous.downcast::<Arc<AtomicBool>>() {
            parsed.store(true, Ordering::Release);
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        session.set_read_timeout(Some(Duration::from_secs(15)));
        session.set_write_timeout(Some(Duration::from_secs(30)));
        session.set_keepalive(Some(15));
        session.set_keepalive_reuses_remaining(Some(1000));
        session.set_close_on_response_before_downstream_finish(true);
        if self.control.is_control_request(session) {
            ctx.control_plane = true;
            return self
                .control
                .handle(
                    session,
                    serde_json::json!({
                        "requests": self.counters.requests.load(Ordering::Relaxed),
                        "blocked": self.counters.blocked.load(Ordering::Relaxed),
                        "observed": self.counters.observed.load(Ordering::Relaxed),
                        "errors": self.counters.errors.load(Ordering::Relaxed),
                        "inflight": self.active.load(Ordering::Relaxed),
                        "buffered_bytes": self.buffered.load(Ordering::Relaxed),
                    }),
                    self.started.elapsed().as_secs(),
                )
                .await;
        }
        self.counters.requests.fetch_add(1, Ordering::Relaxed);
        let req = session.req_header();
        if matches!(req.uri.path(), "/_rustgate/health" | "/_zntil/health")
            && req.method == http::Method::GET
        {
            let mut h = ResponseHeader::build(200, Some(2))?;
            h.insert_header("x-protection", "active")?;
            h.insert_header("content-length", "0")?;
            h.insert_header("cache-control", "no-store")?;
            session.write_response_header(Box::new(h), true).await?;
            return Ok(true);
        }
        if !authenticate(
            req.headers.get("x-rustgate-ingress-token"),
            &self.ingress_token,
        ) {
            return self.reject(session, 403, ctx).await;
        }
        if req.uri.scheme().is_some() || req.method == http::Method::CONNECT {
            return self.reject(session, 400, ctx).await;
        }
        let authority = req.uri.authority().map(|a| a.as_str());
        let host_header = req.headers.get("host").and_then(|v| v.to_str().ok());
        if req.headers.get_all("host").iter().count() > 1 {
            return self.reject(session, 400, ctx).await;
        }
        if let (Some(a), Some(h)) = (authority, host_header)
            && hostname(a) != hostname(h)
        {
            return self.reject(session, 400, ctx).await;
        }
        let Some(host) = host_header.or(authority).and_then(hostname) else {
            return self.reject(session, 400, ctx).await;
        };
        let Some(entry) = self.control.routing.load().hosts.get(&host).cloned() else {
            return self.reject(session, 421, ctx).await;
        };
        ctx.route = Some(entry.clone());
        ctx.host = host;
        let size = req
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.as_bytes().len() + 4)
            .sum::<usize>();
        if size > self.config.max_header_bytes {
            return self.reject(session, 431, ctx).await;
        }
        if req.uri.to_string().len() > self.config.max_uri_bytes {
            return self.reject(session, 414, ctx).await;
        }
        let cl = req.headers.get("content-length");
        if req
            .headers
            .get("content-encoding")
            .is_some_and(|v| v != "identity")
        {
            return self.reject(session, 415, ctx).await;
        }
        ctx.body_kind = waf::BodyKind::from_type(
            req.headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
        );
        if cl.is_some() && req.headers.contains_key("transfer-encoding") {
            return self.reject(session, 400, ctx).await;
        }
        if req.headers.get_all("content-length").iter().count() > 1 {
            return self.reject(session, 400, ctx).await;
        }
        if let Some(v) = cl {
            let Some(n) = v.to_str().ok().and_then(|v| v.parse::<u64>().ok()) else {
                return self.reject(session, 400, ctx).await;
            };
            if n > self.config.max_body_bytes as u64 {
                return self.reject(session, 413, ctx).await;
            }
        }
        if let Some(te) = req.headers.get("transfer-encoding")
            && (req.headers.get_all("transfer-encoding").iter().count() != 1
                || !te.as_bytes().eq_ignore_ascii_case(b"chunked"))
        {
            return self.reject(session, 400, ctx).await;
        }
        if !matches!(
            req.method.as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
        ) {
            return self.reject(session, 405, ctx).await;
        }
        let Some(peer) = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.ip())
        else {
            return self.reject(session, 400, ctx).await;
        };
        let Some(ip) = client_ip(peer, &req.headers, &self.config) else {
            return self.reject(session, 400, ctx).await;
        };
        ctx.ip = Some(ip);
        if req.uri.path() == "/_rustgate/diagnostics" {
            if self.diagnostics_token.is_none()
                || !authenticate(
                    req.headers.get("x-rustgate-diagnostics-token"),
                    &self.diagnostics_token,
                )
            {
                return self.reject(session, 404, ctx).await;
            }
            let body = serde_json::to_vec(
                &serde_json::json!({"peer":peer.to_string(),"client":ip.to_string()}),
            )
            .unwrap();
            let mut h = ResponseHeader::build(200, Some(3))?;
            h.insert_header("x-protection", "active")?;
            h.insert_header("content-length", body.len().to_string())?;
            h.insert_header("content-type", "application/json")?;
            h.insert_header("cache-control", "no-store")?;
            session.write_response_header(Box::new(h), false).await?;
            session
                .write_response_body(Some(Bytes::from(body)), true)
                .await?;
            return Ok(true);
        }
        let trusted = self
            .config
            .trusted_proxies
            .iter()
            .any(|n| n.contains(&peer));
        ctx.scheme = if session.digest().is_some_and(|d| d.ssl_digest.is_some())
            || (trusted
                && req
                    .headers
                    .get("x-forwarded-proto")
                    .is_some_and(|v| v == "https"))
        {
            "https"
        } else {
            "http"
        };
        let Some(path) = normalized_path(req.uri.path()) else {
            return self.reject(session, 400, ctx).await;
        };
        let r = &entry.route;
        if r.body_inspection_exempt_prefixes
            .iter()
            .any(|p| path_matches(&path, p))
        {
            ctx.body_kind = waf::BodyKind::Opaque;
        }
        if !matches!(ctx.body_kind, waf::BodyKind::Opaque)
            && req
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
                .is_some_and(|n| n > self.config.max_inspected_body_bytes)
        {
            return self.reject(session, 413, ctx).await;
        }
        let mut reason = suspicious(&path, r);
        let sensitive = r.sensitive_prefixes.iter().any(|p| path_matches(&path, p));
        let crawler = self.crawlers.verified(
            ip,
            req.headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
        );
        if crawler {
            self.counters.crawlers.fetch_add(1, Ordering::Relaxed);
        }
        let now = Instant::now();
        let global_ok =
            entry
                .global
                .lock()
                .unwrap()
                .take(r.global_requests_per_second, r.global_burst, now);
        if !global_ok {
            return self.reject(session, 503, ctx).await;
        }
        if reason.is_none() && req.uri.query().is_some_and(waf::parameters) {
            reason = Some("injection_query");
        }
        let decision = self.guard.check(
            entry.key,
            ip,
            r,
            &self.config,
            crawler,
            sensitive,
            if reason.is_some() { 4.0 } else { 0.0 },
            now,
        );
        if decision == Decision::Capacity {
            return self.reject(session, 503, ctx).await;
        }
        let behavior_status = match decision {
            Decision::Ban => Some(403),
            Decision::Rate => Some(429),
            _ => reason.map(|_| 403),
        };
        if let Some(status) = behavior_status {
            ctx.reason = reason.unwrap_or(match decision {
                Decision::Ban => "temporary_ban",
                _ => "rate_limit",
            });
            if self.config.mode == Mode::Enforce {
                return self.reject(session, status, ctx).await;
            }
            self.counters.observed.fetch_add(1, Ordering::Relaxed);
            ctx.observed = true;
        }
        if self
            .active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < self.config.max_inflight).then_some(n + 1)
            })
            .is_err()
        {
            return self.reject(session, 503, ctx).await;
        }
        ctx.active = Some(self.active.clone());
        ctx.budget = Some(self.buffered.clone());
        Ok(false)
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        let state = ctx.route.as_ref().expect("route selected before upstream");
        let r = &state.route;
        // Only fixed configured destinations; one DNS lookup at a time per route.
        let mut cache = state.dns.lock().await;
        let address = if let Some((addr, expiry)) = *cache
            && expiry > Instant::now()
        {
            addr
        } else {
            let lookup = tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::lookup_host((r.upstream.as_str(), r.upstream_port)),
            )
            .await
            .map_err(|_| Error::explain(ErrorType::ConnectTimedout, "upstream DNS timeout"))?
            .map_err(|_| Error::explain(ErrorType::ConnectError, "upstream DNS failed"))?;
            let addresses: Vec<_> = lookup.collect();
            let addr = addresses
                .iter()
                .filter(|a| control::destination_allowed(a.ip(), self.config.trust_railway_edge))
                .find(|a| a.is_ipv4())
                .or_else(|| {
                    addresses.iter().find(|a| {
                        control::destination_allowed(a.ip(), self.config.trust_railway_edge)
                    })
                })
                .copied()
                .ok_or_else(|| Error::explain(ErrorType::ConnectError, "upstream DNS empty"))?;
            *cache = Some((addr, Instant::now() + Duration::from_secs(60)));
            addr
        };
        drop(cache);
        let mut peer = HttpPeer::new(address, r.upstream_tls, r.upstream.clone());
        peer.options.connection_timeout = Some(Duration::from_secs(5));
        peer.options.total_connection_timeout = Some(Duration::from_secs(8));
        peer.options.read_timeout = Some(Duration::from_secs(r.upstream_timeout_seconds));
        peer.options.write_timeout = Some(Duration::from_secs(15));
        peer.options.idle_timeout = Some(Duration::from_secs(30));
        peer.options.verify_cert = true;
        peer.options.verify_hostname = true;
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        req: &mut RequestHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let connection_tokens: Vec<String> = req
            .headers
            .get_all("connection")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(',').map(|s| s.trim().to_ascii_lowercase()))
            .collect();
        let websocket = req
            .headers
            .get("upgrade")
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
            && connection_tokens.iter().any(|v| v == "upgrade");
        for name in connection_tokens {
            if !matches!(
                name.as_str(),
                "upgrade" | "host" | "content-length" | "transfer-encoding"
            ) {
                req.remove_header(&name);
            }
        }
        for name in [
            "forwarded",
            "x-forwarded-for",
            "x-real-ip",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "cf-connecting-ip",
            "true-client-ip",
            "x-rustgate-ingress-token",
            "x-rustgate-origin-token",
            "x-rustgate-diagnostics-token",
            "proxy-authorization",
            "proxy-connection",
            "keep-alive",
            "te",
            "trailer",
        ] {
            req.remove_header(name);
        }
        if !websocket {
            req.remove_header("upgrade");
            req.remove_header("connection");
        } else {
            req.insert_header("connection", "upgrade")?;
        }
        req.insert_header("x-real-ip", ctx.ip.unwrap().to_string())?;
        req.insert_header("x-forwarded-for", ctx.ip.unwrap().to_string())?;
        let state = ctx.route.as_ref().expect("route selected before upstream");
        let r = &state.route;
        req.insert_header(
            "x-forwarded-host",
            r.forwarded_host.as_deref().unwrap_or(&ctx.host),
        )?;
        req.insert_header(
            "x-forwarded-proto",
            r.public_scheme.as_deref().unwrap_or(ctx.scheme),
        )?;
        req.insert_header("host", r.upstream_host.as_deref().unwrap_or(&ctx.host))?;
        if let Some(token) = &state.origin_token {
            req.insert_header("x-rustgate-origin-token", token.as_str())?;
        }
        Ok(())
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end: bool,
        ctx: &mut Ctx,
    ) -> Result<()> {
        if ctx.tunnel {
            return Ok(());
        }
        ctx.body_bytes = ctx
            .body_bytes
            .saturating_add(body.as_ref().map_or(0, Bytes::len));
        let limit = if matches!(ctx.body_kind, waf::BodyKind::Opaque) {
            self.config.max_body_bytes
        } else {
            self.config
                .max_body_bytes
                .min(self.config.max_inspected_body_bytes)
        };
        if ctx.body_bytes > limit {
            ctx.blocked = true;
            ctx.reason = "body_size_limit";
            *body = None;
            return Error::e_explain(ErrorType::HTTPStatus(413), "request body limit exceeded");
        }
        if ctx.started.elapsed() > Duration::from_secs(60) {
            ctx.blocked = true;
            ctx.reason = "upload_timeout";
            *body = None;
            return Error::e_explain(ErrorType::HTTPStatus(408), "upload duration exceeded");
        }
        if !matches!(ctx.body_kind, waf::BodyKind::Opaque) {
            let n = body.as_ref().map_or(0, Bytes::len);
            if self
                .buffered
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                    used.checked_add(n)
                        .filter(|total| *total <= self.config.max_buffered_body_bytes)
                })
                .is_err()
            {
                ctx.blocked = true;
                ctx.reason = "inspection_capacity";
                *body = None;
                return Error::e_explain(
                    ErrorType::HTTPStatus(503),
                    "inspection memory budget exhausted",
                );
            }
            ctx.reserved += n;
            if let Some(chunk) = body.take() {
                ctx.buffer.extend_from_slice(&chunk);
            }
            if end {
                if !ctx.buffer.is_empty() && waf::body(ctx.body_kind, &ctx.buffer) {
                    if self.config.mode == Mode::Enforce {
                        ctx.blocked = true;
                        ctx.reason = "body_injection";
                        self.counters.blocked.fetch_add(1, Ordering::Relaxed);
                        return Error::e_explain(
                            ErrorType::HTTPStatus(403),
                            "body inspection rejected request",
                        );
                    }
                    self.counters.observed.fetch_add(1, Ordering::Relaxed);
                    ctx.observed = true;
                    ctx.reason = "body_injection";
                }
                *body = Some(ctx.buffer.split().freeze());
            } else {
                // Pingora interprets None as end-of-body; an empty chunk defers output.
                *body = Some(Bytes::new());
            }
        }
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        ctx.tunnel = response.status == http::StatusCode::SWITCHING_PROTOCOLS;
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        response: &mut ResponseHeader,
        _ctx: &mut Ctx,
    ) -> Result<()> {
        response.insert_header("x-protection", "active")?;
        Ok(())
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Ctx) {
        if ctx.control_plane {
            return;
        }
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(if e.is_some() { 500 } else { 0 });
        self.control.record(control::Event {
            time: control::now(),
            host: ctx.host.clone(),
            method: session
                .req_header()
                .method
                .as_str()
                .chars()
                .take(16)
                .collect(),
            status,
            outcome: if ctx.blocked {
                "blocked"
            } else if e.is_some() || status >= 500 {
                "error"
            } else if ctx.observed {
                "observed"
            } else {
                "allowed"
            },
            reason: ctx.reason,
            latency_ms: ctx.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        });
        if let Some(e) = e {
            self.counters.errors.fetch_add(1, Ordering::Relaxed);
            log::debug!("proxy error type={:?}", e.etype());
        }
        // Aggregate logs avoid recording credentials and per-request logging under floods.
        let elapsed = self.started.elapsed().as_secs();
        let previous = self.last_report.load(Ordering::Relaxed);
        if elapsed >= previous + 30
            && self
                .last_report
                .compare_exchange(previous, elapsed, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            log::info!(
                "requests={} blocked={} observed={} verified_crawlers={} errors={} inflight={}",
                self.counters.requests.load(Ordering::Relaxed),
                self.counters.blocked.load(Ordering::Relaxed),
                self.counters.observed.load(Ordering::Relaxed),
                self.counters.crawlers.load(Ordering::Relaxed),
                self.counters.errors.load(Ordering::Relaxed),
                self.active.load(Ordering::Relaxed)
            );
        }
    }

    fn suppress_error_log(&self, _session: &Session, _ctx: &Ctx, _error: &Error) -> bool {
        // The framework default includes the request URI, which can contain capability tokens.
        true
    }
    fn request_summary(&self, _session: &Session, ctx: &Ctx) -> String {
        // Retry warnings must not expose application capability URLs either.
        format!("zntil route={}", ctx.route.as_ref().map_or(0, |r| r.key))
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("zntil=info,pingora=error"),
    )
    .init();
    let path = std::env::var("ZNTIL_CONFIG")
        .or_else(|_| std::env::var("RUSTGATE_CONFIG"))
        .unwrap_or_else(|_| "config/local.toml".into());
    let config = Config::load(&path)?;
    let gateway = Gateway::new(config.clone())?;
    if std::env::args().any(|s| s == "--check") {
        println!(
            "Configuration valid: {} routes, {:?} mode",
            config.routes.len(),
            config.mode
        );
        return Ok(());
    }
    let conf = pingora::server::configuration::ServerConf {
        // Pingora counts the initial attempt in max_retries; one means no replay.
        threads: config.threads,
        upstream_keepalive_pool_size: 64,
        max_retries: 1,
        grace_period_seconds: Some(1),
        graceful_shutdown_timeout_seconds: Some(10),
        max_blocking_threads: Some(4),
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();
    let transport = Transport {
        app: Arc::new(pingora::proxy::http_proxy(&server.configuration, gateway)),
        slots: tokio::sync::Semaphore::new(config.max_connections),
        header_timeout: Duration::from_secs(config.header_timeout_seconds),
    };
    let mut proxy = pingora::services::listening::Service::new("Zntil".into(), transport);
    proxy.set_connection_filter(Arc::new(Admission {
        bucket: Mutex::new(Bucket::new(config.connection_burst, Instant::now())),
        rate: config.connections_per_second,
        burst: config.connection_burst,
    }));
    proxy.add_tcp(&config.listen);
    if let (Some(cert), Some(key)) = (&config.tls_cert, &config.tls_key) {
        proxy.add_tls(&config.tls_listen, cert, key)?;
    }
    log::info!(
        "zntil listening={} routes={} mode={:?}",
        config.listen,
        config.routes.len(),
        config.mode
    );
    server.add_service(proxy);
    server.run_forever();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forwarded_ip_spoofing() {
        let mut h = http::HeaderMap::new();
        h.insert("x-real-ip", "192.0.2.1".parse().unwrap());
        let mut c = Config::default();
        let peer = "198.51.100.1".parse().unwrap();
        assert_eq!(client_ip(peer, &h, &c), Some(peer));
        c.trusted_proxies.push("198.51.100.0/24".parse().unwrap());
        assert_eq!(client_ip(peer, &h, &c), Some("192.0.2.1".parse().unwrap()));
        h.append("x-real-ip", "192.0.2.2".parse().unwrap());
        assert_eq!(client_ip(peer, &h, &c), None);
    }
    #[test]
    fn token_validation() {
        let expected = Some("test-secret".to_string());
        assert!(!authenticate(None, &expected));
        assert!(!authenticate(Some(&"wrong".parse().unwrap()), &expected));
        assert!(authenticate(
            Some(&"test-secret".parse().unwrap()),
            &expected
        ));
    }
    #[test]
    fn inflight_released_on_context_drop() {
        let a = Arc::new(AtomicUsize::new(1));
        {
            let mut ctx = Ctx::default();
            ctx.active = Some(a.clone());
        }
        assert_eq!(a.load(Ordering::Relaxed), 0);
    }
}
