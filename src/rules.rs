use crate::{
    config::{Route, hostname},
    guard::normalized_path,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    Block,
    RateLimit,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathMatch {
    #[default]
    Prefix,
    Exact,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub domains: Vec<String>,
    pub path: String,
    pub path_match: PathMatch,
    pub methods: Vec<String>,
    pub client_cidrs: Vec<IpNet>,
    pub action: Action,
    pub requests_per_second: Option<f64>,
    pub burst: Option<f64>,
}
impl Default for Rule {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: true,
            domains: vec![],
            path: "/".into(),
            path_match: PathMatch::Prefix,
            methods: vec![],
            client_cidrs: vec![],
            action: Action::Block,
            requests_per_second: None,
            burst: None,
        }
    }
}
impl Rule {
    pub fn matches(&self, host: &str, path: &str, method: &str, ip: IpAddr) -> bool {
        self.enabled
            && (self.domains.is_empty() || self.domains.iter().any(|d| d == host))
            && (self.methods.is_empty() || self.methods.iter().any(|m| m == method))
            && (self.client_cidrs.is_empty() || self.client_cidrs.iter().any(|n| n.contains(&ip)))
            && match self.path_match {
                PathMatch::Exact => path == self.path,
                PathMatch::Prefix => {
                    let prefix = self.path.trim_end_matches('/');
                    prefix.is_empty()
                        || path == prefix
                        || path
                            .strip_prefix(prefix)
                            .is_some_and(|tail| tail.starts_with('/'))
                }
            }
    }
}
pub fn validate(route: &Route) -> Result<(), Box<dyn std::error::Error>> {
    if route.rules.len() > 128 {
        return Err("at most 128 custom rules per proxy".into());
    }
    let mut ids = HashSet::new();
    for r in &route.rules {
        if r.id.is_empty()
            || r.id.len() > 64
            || !r
                .id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            || !ids.insert(&r.id)
            || r.name.is_empty()
            || r.name.len() > 120
            || r.path.len() > 2048
            || !r.path.starts_with('/')
            || r.path.contains(['?', '#'])
            || normalized_path(&r.path).as_deref() != Some(r.path.as_str())
            || r.domains.len() > 64
            || r.methods.len() > 7
            || r.client_cidrs.len() > 64
        {
            return Err("invalid rule ID, name, normalized path or match dimensions".into());
        }
        if r.domains
            .iter()
            .any(|d| hostname(d).as_deref() != Some(d.as_str()) || !route.hosts.contains(d))
        {
            return Err("rule domains must belong to the proxy".into());
        }
        if r.methods.iter().any(|m| {
            !matches!(
                m.as_str(),
                "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
            )
        }) {
            return Err("rule methods must be uppercase supported HTTP methods".into());
        }
        match r.action {
            Action::Block if r.requests_per_second.is_some() || r.burst.is_some() => {
                return Err("block rules cannot define rate limits".into());
            }
            Action::RateLimit
                if r.requests_per_second
                    .is_none_or(|n| !n.is_finite() || n <= 0.0)
                    || r.burst.is_none_or(|n| !n.is_finite() || n < 1.0) =>
            {
                return Err("rate rules require a positive rate and burst of at least one".into());
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_method_cidr_and_segment_boundaries() {
        let r = Rule {
            id: "a".into(),
            name: "admin".into(),
            domains: vec!["a.test".into()],
            path: "/admin".into(),
            methods: vec!["POST".into()],
            client_cidrs: vec!["192.0.2.0/24".parse().unwrap()],
            ..Default::default()
        };
        let ip = "192.0.2.10".parse().unwrap();
        assert!(r.matches("a.test", "/admin/users", "POST", ip));
        assert!(!r.matches("a.test", "/administrator", "POST", ip));
        assert!(!r.matches("b.test", "/admin", "POST", ip));
        assert!(!r.matches("a.test", "/admin", "GET", ip));
        assert!(!r.matches("a.test", "/admin", "POST", "198.51.100.1".parse().unwrap()));
    }
    #[test]
    fn root_and_trailing_slash_prefixes() {
        let ip = "127.0.0.1".parse().unwrap();
        let mut rule = Rule::default();
        assert!(rule.matches("a.test", "/anything", "GET", ip));
        rule.path = "/admin/".into();
        assert!(rule.matches("a.test", "/admin/users", "GET", ip));
        assert!(!rule.matches("a.test", "/administrator", "GET", ip));
        rule.path_match = PathMatch::Exact;
        assert!(!rule.matches("a.test", "/admin/users", "GET", ip));
    }
    #[test]
    fn invalid_rules_rejected() {
        let mut route = Route {
            hosts: vec!["a.test".into()],
            rules: vec![Rule {
                id: "a".into(),
                name: "one".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(validate(&route).is_ok());
        route.rules[0].action = Action::RateLimit;
        assert!(validate(&route).is_err());
        route.rules[0].requests_per_second = Some(2.0);
        route.rules[0].burst = Some(3.0);
        assert!(validate(&route).is_ok());
        route.rules[0].domains = vec!["b.test".into()];
        assert!(validate(&route).is_err());
    }
}
