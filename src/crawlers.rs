use ipnet::IpNet;
use serde::Deserialize;
use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Crawlers {
    pub expires_at: u64,
    pub bots: Vec<Bot>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bot {
    pub name: String,
    pub user_agent: String,
    pub networks: Vec<IpNet>,
}
impl Crawlers {
    pub fn load(path: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        match path {
            None => Ok(Self::default()),
            Some(p) => {
                let raw = std::fs::read(p)?;
                if raw.len() > 2 * 1024 * 1024 {
                    return Err("crawler file exceeds 2 MB".into());
                }
                let c: Self = serde_json::from_slice(&raw)?;
                if c.bots.iter().any(|b| {
                    b.name.is_empty()
                        || b.user_agent.is_empty()
                        || b.networks.iter().any(|n| n.prefix_len() == 0)
                }) {
                    return Err("invalid crawler definition".into());
                }
                Ok(c)
            }
        }
    }
    pub fn verified(&self, ip: IpAddr, ua: &str) -> bool {
        self.verified_at(
            ip,
            ua,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
    }
    fn verified_at(&self, ip: IpAddr, ua: &str, now: u64) -> bool {
        now < self.expires_at
            && self.bots.iter().any(|b| {
                ua.contains(&b.user_agent) && b.networks.iter().any(|net| net.contains(&ip))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_requires_ip_and_fresh_feed() {
        let c = Crawlers {
            expires_at: 100,
            bots: vec![Bot {
                name: "Googlebot".into(),
                user_agent: "Googlebot".into(),
                networks: vec!["192.0.2.0/24".parse().unwrap()],
            }],
        };
        assert!(c.verified_at("192.0.2.1".parse().unwrap(), "Googlebot", 99));
        assert!(!c.verified_at("198.51.100.1".parse().unwrap(), "Googlebot", 99));
        assert!(!c.verified_at("192.0.2.1".parse().unwrap(), "Googlebot", 100));
        assert!(!c.verified_at("192.0.2.1".parse().unwrap(), "browser", 99));
    }
}
