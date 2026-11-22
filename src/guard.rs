use crate::config::{Config, Route};
use percent_encoding::percent_decode_str;
use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub struct Bucket {
    tokens: f64,
    last: Instant,
}
impl Bucket {
    pub fn new(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            last: now,
        }
    }
    pub fn take(&mut self, rate: f64, burst: f64, now: Instant) -> bool {
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * rate).min(burst);
        self.last = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

struct Client {
    bucket: Bucket,
    sensitive: Bucket,
    score: f64,
    score_at: Instant,
    seen: Instant,
    banned_until: Option<Instant>,
}
struct Shard {
    clients: HashMap<(usize, IpAddr), Client>,
    last_gc: Instant,
}
pub struct Guard {
    shards: Vec<Mutex<Shard>>,
    capacity: usize,
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    Allow,
    Rate,
    Ban,
    Capacity,
}

impl Guard {
    pub fn new(capacity: usize) -> Self {
        Self {
            shards: (0..16)
                .map(|_| {
                    Mutex::new(Shard {
                        clients: HashMap::new(),
                        last_gc: Instant::now(),
                    })
                })
                .collect(),
            capacity: capacity / 16,
        }
    }
    #[allow(clippy::too_many_arguments)] // Shared policy and request facts stay allocation-free.
    pub fn check(
        &self,
        route: usize,
        ip: IpAddr,
        r: &Route,
        c: &Config,
        crawler: bool,
        sensitive: bool,
        points: f64,
        now: Instant,
    ) -> Decision {
        let key = (route, ip);
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        let mut shard = self.shards[h.finish() as usize % self.shards.len()]
            .lock()
            .unwrap();
        if now.duration_since(shard.last_gc) >= Duration::from_secs(5) {
            shard.clients.retain(|_, v| {
                now.duration_since(v.seen) < Duration::from_secs(c.client_ttl_seconds)
                    || v.banned_until.is_some_and(|until| until > now)
            });
            shard.last_gc = now;
        }
        if !shard.clients.contains_key(&key) && shard.clients.len() >= self.capacity {
            return Decision::Capacity;
        }
        let (rate, burst) = if crawler {
            (r.crawler_requests_per_second, r.crawler_burst)
        } else {
            (r.requests_per_second, r.burst)
        };
        let client = shard.clients.entry(key).or_insert_with(|| Client {
            bucket: Bucket::new(burst, now),
            sensitive: Bucket::new(r.sensitive_burst, now),
            score: 0.0,
            score_at: now,
            seen: now,
            banned_until: None,
        });
        client.seen = now;
        client.score = (client.score
            - now.duration_since(client.score_at).as_secs_f64() * c.score_decay_per_second)
            .max(0.0);
        client.score_at = now;
        if client.banned_until.is_some_and(|until| until > now) {
            return Decision::Ban;
        }
        client.banned_until = None;
        client.score = (client.score + points).min(c.score_threshold * 2.0);
        if client.score >= c.score_threshold {
            client.banned_until = Some(now + Duration::from_secs(c.ban_seconds));
            client.score = 0.0;
            return Decision::Ban;
        }
        if !client.bucket.take(rate, burst, now) {
            return Decision::Rate;
        }
        if sensitive
            && !client
                .sensitive
                .take(r.sensitive_requests_per_second, r.sensitive_burst, now)
        {
            return Decision::Rate;
        }
        Decision::Allow
    }
}

pub fn normalized_path(path: &str) -> Option<String> {
    let mut s = path.to_owned();
    // Decode a bounded number of layers, then reject residual encodings rather than guessing.
    for _ in 0..3 {
        let decoded = percent_decode_str(&s).decode_utf8().ok()?.into_owned();
        if decoded == s {
            break;
        }
        s = decoded;
    }
    if s.contains('%') || s.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f) {
        return None;
    }
    let s = s.replace('\\', "/").to_ascii_lowercase();
    let mut parts = vec![];
    for part in s.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    Some(format!("/{}", parts.join("/")))
}

pub fn path_matches(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|s| s.starts_with('/') || s.starts_with('.'))
}

pub fn suspicious(path: &str, route: &Route) -> Option<&'static str> {
    if route.deny_prefixes.iter().any(|p| path_matches(path, p)) {
        return Some("probe_path");
    }
    if path.split('/').any(|p| p == "etc") && path.ends_with("/passwd") {
        return Some("sensitive_file_probe");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refill() {
        let n = Instant::now();
        let mut b = Bucket::new(2.0, n);
        assert!(b.take(1.0, 2.0, n));
        assert!(b.take(1.0, 2.0, n));
        assert!(!b.take(1.0, 2.0, n));
        assert!(b.take(1.0, 2.0, n + Duration::from_secs(1)));
    }
    #[test]
    fn encoded_probes() {
        let r = Route::default();
        for p in [
            "/.git/config",
            "/%252egit/config",
            "/a/../.env",
            "//.git/config",
            "/%2eenv.local",
            "/%2e%2e/etc/passwd",
        ] {
            assert!(
                suspicious(&normalized_path(p).unwrap(), &r).is_some(),
                "{p}"
            );
        }
        assert!(suspicious("/.github", &r).is_none());
        assert!(normalized_path("/%00").is_none());
    }
    #[test]
    fn ban_expires_and_hosts_are_separate() {
        let g = Guard::new(1024);
        let c = Config::default();
        let r = Route::default();
        let n = Instant::now();
        let ip = "192.0.2.1".parse().unwrap();
        for _ in 0..2 {
            assert_eq!(
                g.check(0, ip, &r, &c, false, false, 4.0, n),
                Decision::Allow
            );
        }
        assert_eq!(g.check(0, ip, &r, &c, false, false, 4.0, n), Decision::Ban);
        assert_eq!(
            g.check(1, ip, &r, &c, false, false, 0.0, n),
            Decision::Allow
        );
        assert_eq!(
            g.check(
                0,
                ip,
                &r,
                &c,
                false,
                false,
                0.0,
                n + Duration::from_secs(61)
            ),
            Decision::Allow
        );
    }
    #[test]
    fn bounded_under_unique_ips() {
        let g = Guard::new(16);
        let c = Config::default();
        let r = Route::default();
        let n = Instant::now();
        let mut capacity = 0;
        for i in 1..1000 {
            if g.check(
                0,
                IpAddr::V4(std::net::Ipv4Addr::from(i)),
                &r,
                &c,
                false,
                false,
                0.0,
                n,
            ) == Decision::Capacity
            {
                capacity += 1;
            }
        }
        assert!(capacity >= 983);
        assert!(
            g.shards
                .iter()
                .map(|s| s.lock().unwrap().clients.len())
                .sum::<usize>()
                <= 16
        );
    }
    #[test]
    fn sensitive_budget_separate() {
        let g = Guard::new(1024);
        let c = Config::default();
        let r = Route {
            sensitive_burst: 1.0,
            ..Route::default()
        };
        let n = Instant::now();
        let ip = "192.0.2.1".parse().unwrap();
        assert_eq!(g.check(0, ip, &r, &c, false, true, 0.0, n), Decision::Allow);
        assert_eq!(g.check(0, ip, &r, &c, false, true, 0.0, n), Decision::Rate);
        assert_eq!(
            g.check(0, ip, &r, &c, false, false, 0.0, n),
            Decision::Allow
        );
    }
}
