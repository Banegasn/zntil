use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, net::SocketAddr};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Observe,
    Enforce,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub threads: usize,
    pub mode: Mode,
    pub max_clients: usize,
    pub max_inflight: usize,
    pub max_connections: usize,
    pub header_timeout_seconds: u64,
    pub connections_per_second: f64,
    pub connection_burst: f64,
    pub max_header_bytes: usize,
    pub max_uri_bytes: usize,
    pub max_body_bytes: usize,
    pub max_inspected_body_bytes: usize,
    pub max_buffered_body_bytes: usize,
    pub client_ttl_seconds: u64,
    pub ban_seconds: u64,
    pub score_threshold: f64,
    pub score_decay_per_second: f64,
    pub trusted_proxies: Vec<IpNet>,
    pub trust_railway_edge: bool,
    pub diagnostics_token_env: Option<String>,
    pub admin_token_env: Option<String>,
    pub admin_data_dir: Option<String>,
    pub admin_host: Option<String>,
    pub crawler_file: Option<String>,
    pub ingress_token_env: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub tls_listen: String,
    pub routes: Vec<Route>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".into(),
            threads: 1,
            mode: Mode::Observe,
            max_clients: 16384,
            max_inflight: 256,
            max_connections: 512,
            header_timeout_seconds: 10,
            connections_per_second: 50.0,
            connection_burst: 100.0,
            max_header_bytes: 16384,
            max_uri_bytes: 8192,
            max_body_bytes: 2 * 1024 * 1024,
            max_inspected_body_bytes: 2 * 1024 * 1024,
            max_buffered_body_bytes: 16 * 1024 * 1024,
            client_ttl_seconds: 600,
            ban_seconds: 60,
            score_threshold: 12.0,
            score_decay_per_second: 0.1,
            trusted_proxies: vec![],
            trust_railway_edge: false,
            diagnostics_token_env: None,
            admin_token_env: None,
            admin_data_dir: None,
            admin_host: None,
            crawler_file: None,
            ingress_token_env: None,
            tls_cert: None,
            tls_key: None,
            tls_listen: "0.0.0.0:8443".into(),
            routes: vec![],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Route {
    pub hosts: Vec<String>,
    pub upstream: String,
    pub upstream_port: u16,
    pub upstream_tls: bool,
    pub upstream_host: Option<String>,
    pub forwarded_host: Option<String>,
    pub public_scheme: Option<String>,
    pub body_inspection_exempt_prefixes: Vec<String>,
    pub origin_token_env: Option<String>,
    pub requests_per_second: f64,
    pub burst: f64,
    pub crawler_requests_per_second: f64,
    pub crawler_burst: f64,
    pub global_requests_per_second: f64,
    pub global_burst: f64,
    pub sensitive_prefixes: Vec<String>,
    pub sensitive_requests_per_second: f64,
    pub sensitive_burst: f64,
    pub deny_prefixes: Vec<String>,
    pub upstream_timeout_seconds: u64,
}
impl Default for Route {
    fn default() -> Self {
        Self {
            hosts: vec![],
            upstream: String::new(),
            upstream_port: 8080,
            upstream_tls: false,
            upstream_host: None,
            forwarded_host: None,
            public_scheme: None,
            body_inspection_exempt_prefixes: vec![],
            origin_token_env: None,
            requests_per_second: 10.0,
            burst: 100.0,
            crawler_requests_per_second: 5.0,
            crawler_burst: 30.0,
            global_requests_per_second: 200.0,
            global_burst: 400.0,
            sensitive_prefixes: vec!["/login".into(), "/admin".into(), "/v1/auth".into()],
            sensitive_requests_per_second: 0.5,
            sensitive_burst: 10.0,
            deny_prefixes: vec![
                "/.git".into(),
                "/.env".into(),
                "/wp-login.php".into(),
                "/wp-admin".into(),
                "/xmlrpc.php".into(),
                "/vendor/phpunit".into(),
            ],
            upstream_timeout_seconds: 60,
        }
    }
}

pub fn hostname(value: &str) -> Option<String> {
    let authority: http::uri::Authority = value.parse().ok()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return None;
    }
    Some(host)
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config: Self = toml::from_str(&fs::read_to_string(path)?)?;
        if let Ok(port) = std::env::var("PORT") {
            let port: u16 = port.parse()?;
            if port == 0 {
                return Err("PORT cannot be zero".into());
            }
            config.listen = format!("0.0.0.0:{port}");
        }
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _: SocketAddr = self.listen.parse()?;
        let _: SocketAddr = self.tls_listen.parse()?;
        if self.threads == 0
            || self.threads > 64
            || self.max_clients < 16
            || self.max_clients > 1_000_000
            || self.max_inflight == 0
            || self.max_connections == 0
            || self.header_timeout_seconds == 0
            || self.max_header_bytes < 1024
            || self.max_uri_bytes == 0
            || self.max_body_bytes == 0
            || self.max_inspected_body_bytes == 0
            || self.max_buffered_body_bytes < self.max_inspected_body_bytes
            || self.client_ttl_seconds == 0
            || self.ban_seconds == 0
            || self.client_ttl_seconds < self.ban_seconds
            || self.routes.is_empty()
            || !self.score_threshold.is_finite()
            || self.score_threshold <= 0.0
            || !self.score_decay_per_second.is_finite()
            || self.score_decay_per_second <= 0.0
        {
            return Err("invalid resource limits, score settings, or missing routes".into());
        }
        if !self.connections_per_second.is_finite()
            || self.connections_per_second <= 0.0
            || !self.connection_burst.is_finite()
            || self.connection_burst < 1.0
        {
            return Err("invalid connection admission limits".into());
        }
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            return Err("provide both TLS certificate and key".into());
        }
        if self.admin_token_env.is_some() != self.admin_data_dir.is_some() {
            return Err("management requires both admin_token_env and admin_data_dir".into());
        }
        if self.trust_railway_edge && self.admin_token_env.is_some() && self.admin_host.is_none() {
            return Err("set a dedicated admin_host for Railway management".into());
        }
        if self
            .admin_host
            .as_ref()
            .is_some_and(|h| hostname(h).as_deref() != Some(h.as_str()))
        {
            return Err("invalid admin_host".into());
        }
        if self.trusted_proxies.iter().any(|n| n.prefix_len() == 0) {
            return Err("refusing trust of the entire internet as a proxy".into());
        }
        let mut hosts = HashSet::new();
        for r in &self.routes {
            if hostname(&r.upstream).as_deref() != Some(r.upstream.as_str())
                || r.upstream_port == 0
                || r.hosts.is_empty()
                || r.upstream_timeout_seconds == 0
            {
                return Err("invalid upstream or empty host list".into());
            }
            if let Some(h) = &r.upstream_host {
                let _: http::HeaderValue = h.parse()?;
                if hostname(h).is_none() {
                    return Err("invalid upstream Host".into());
                }
            }
            if r.forwarded_host
                .as_ref()
                .is_some_and(|h| hostname(h).as_deref() != Some(h.as_str()))
            {
                return Err("invalid forwarded host".into());
            }
            if r.public_scheme
                .as_ref()
                .is_some_and(|s| s != "https" && s != "http")
            {
                return Err("public_scheme must be https or http".into());
            }
            for h in &r.hosts {
                if hostname(h).as_deref() != Some(h.as_str()) || h.contains(':') || !hosts.insert(h)
                {
                    return Err("hosts must be unique lowercase DNS names without ports".into());
                }
            }
            for v in [
                r.requests_per_second,
                r.burst,
                r.crawler_requests_per_second,
                r.crawler_burst,
                r.global_requests_per_second,
                r.global_burst,
                r.sensitive_requests_per_second,
                r.sensitive_burst,
            ] {
                if !v.is_finite() || v <= 0.0 {
                    return Err("rates and bursts must be finite and positive".into());
                }
            }
            if [r.burst, r.crawler_burst, r.global_burst, r.sensitive_burst]
                .iter()
                .any(|v| *v < 1.0)
            {
                return Err("bursts must be at least one request".into());
            }
            for p in r
                .deny_prefixes
                .iter()
                .chain(&r.sensitive_prefixes)
                .chain(&r.body_inspection_exempt_prefixes)
            {
                if !p.starts_with('/') || p.len() > self.max_uri_bytes {
                    return Err("invalid path prefix".into());
                }
            }
        }
        Ok(())
    }
}

pub fn secret(name: &Option<String>) -> Result<Option<String>, Box<dyn std::error::Error>> {
    name.as_ref()
        .map(|name| {
            let value = std::env::var(name)?;
            if value.len() < 32 {
                return Err("configured secrets must have at least 32 characters".into());
            }
            let _: http::HeaderValue = value.parse()?;
            Ok(value)
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalize_host() {
        assert_eq!(
            hostname("BANEGASN.DEV.:443").as_deref(),
            Some("example.com")
        );
        assert!(hostname("user@example.com").is_none());
        assert!(hostname("evil/path").is_none());
    }
    #[test]
    fn fail_closed_config() {
        let mut c = Config {
            routes: vec![Route {
                hosts: vec!["a.test".into()],
                upstream: "127.0.0.1".into(),
                ..Route::default()
            }],
            ..Config::default()
        };
        assert!(c.validate().is_ok());
        c.routes.push(c.routes[0].clone());
        assert!(c.validate().is_err());
        c.routes.pop();
        c.trusted_proxies.push("0.0.0.0/0".parse().unwrap());
        assert!(c.validate().is_err());
    }
}
