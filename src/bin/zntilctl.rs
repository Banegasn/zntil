use clap::{Args, Parser, Subcommand, ValueEnum};
use reqwest::{StatusCode, Url, blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    name = "zntilctl",
    version,
    about = "Configure a Zntil gateway from a terminal or an agent. Outputs JSON; credentials never appear in command arguments."
)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Gateway origin; defaults to ZNTIL_GATEWAY or the saved login"
    )]
    gateway: Option<String>,
    #[arg(long, global = true, help = "Validate changes without applying them")]
    dry_run: bool,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    #[command(subcommand)]
    Auth(AuthCommand),
    /// Show gateway state, traffic and current configuration.
    Status,
    #[command(subcommand)]
    Config(ConfigCommand),
    #[command(subcommand)]
    Servers(ServerCommand),
    #[command(subcommand)]
    Proxies(ProxyCommand),
    #[command(subcommand)]
    Rules(RuleCommand),
}
#[derive(Subcommand)]
enum AuthCommand {
    /// Sign in by approving a short code in the web console. Expires after 30 days.
    Login {
        #[arg(long, default_value = "Zntil CLI")]
        name: String,
        #[arg(long)]
        read_only: bool,
        #[arg(long)]
        no_browser: bool,
    },
    Status,
    /// Revoke this CLI credential and remove the saved login.
    Logout,
}
#[derive(Subcommand)]
enum ConfigCommand {
    /// Export revision, servers and proxies; safe to edit and apply atomically.
    Get {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Validate a JSON document. Use --file - to read stdin.
    Validate {
        #[arg(long)]
        file: PathBuf,
    },
    /// Apply a JSON document with its expected revision; conflicts return 409.
    Apply {
        #[arg(long)]
        file: PathBuf,
    },
    /// Restore a previous saved revision as a new revision.
    Rollback {
        #[arg(long)]
        revision: u64,
    },
}
#[derive(Subcommand)]
enum ServerCommand {
    List,
    Upsert(ServerArgs),
    Remove {
        #[arg(long)]
        id: String,
    },
}
#[derive(Args)]
struct ServerArgs {
    #[arg(long)]
    id: String,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long, conflicts_with = "http")]
    tls: bool,
    #[arg(long, conflicts_with = "tls")]
    http: bool,
    #[arg(long)]
    origin_token_env: Option<String>,
}
#[derive(Subcommand)]
enum ProxyCommand {
    List,
    Upsert(ProxyArgs),
    Remove {
        #[arg(long)]
        id: String,
    },
}
#[derive(Args)]
struct ProxyArgs {
    #[arg(long)]
    id: String,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    server: Option<String>,
    #[arg(long, value_delimiter = ',')]
    domain: Vec<String>,
    #[arg(long)]
    upstream_host: Option<String>,
    #[arg(long, conflicts_with = "disable")]
    enable: bool,
    #[arg(long, conflicts_with = "enable")]
    disable: bool,
    #[arg(long)]
    rate: Option<f64>,
    #[arg(long)]
    burst: Option<f64>,
    #[arg(long)]
    global_rate: Option<f64>,
    #[arg(long)]
    global_burst: Option<f64>,
}
#[derive(Clone, ValueEnum)]
enum Action {
    Block,
    RateLimit,
}
#[derive(Clone, ValueEnum)]
enum MatchType {
    Prefix,
    Exact,
}
#[derive(Subcommand)]
enum RuleCommand {
    List {
        #[arg(long)]
        proxy: Option<String>,
    },
    Upsert(RuleArgs),
    Remove {
        #[arg(long)]
        proxy: String,
        #[arg(long)]
        id: String,
    },
}
#[derive(Args)]
struct RuleArgs {
    #[arg(long)]
    proxy: String,
    #[arg(long)]
    id: String,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    path: Option<String>,
    #[arg(long, value_enum)]
    match_type: Option<MatchType>,
    #[arg(long, value_enum)]
    action: Option<Action>,
    #[arg(long, value_delimiter = ',')]
    domain: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    method: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    cidr: Vec<String>,
    #[arg(long)]
    rate: Option<f64>,
    #[arg(long)]
    burst: Option<f64>,
    #[arg(long, conflicts_with = "disable")]
    enable: bool,
    #[arg(long, conflicts_with = "enable")]
    disable: bool,
}
#[derive(Serialize, Deserialize)]
struct Login {
    gateway: String,
    token: String,
    token_id: String,
    expires_at: u64,
    scope: String,
}
struct Gateway {
    origin: String,
    token: Option<String>,
    client: Client,
}
fn credential_path() -> Result<PathBuf> {
    if let Some(p) = env::var_os("ZNTIL_CREDENTIALS_FILE") {
        return Ok(p.into());
    }
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or("Set ZNTIL_CREDENTIALS_FILE or XDG_CONFIG_HOME.")?;
    Ok(base.join("zntil/credentials.json"))
}
fn load_login() -> Result<Option<Login>> {
    let path = credential_path()?;
    if !path.exists() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&path)?.permissions().mode() & 0o077 != 0 {
            return Err(
                "Credentials file must have mode 0600; refusing to read an exposed token.".into(),
            );
        }
    }
    let raw = fs::read(&path)?;
    if raw.len() > 16384 {
        return Err("Credentials file is too large.".into());
    }
    Ok(Some(serde_json::from_slice(&raw)?))
}
fn save_login(login: &Login) -> Result<()> {
    let path = credential_path()?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(parent)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(&serde_json::to_vec(login)?)?;
    f.sync_all()?;
    fs::rename(tmp, path)?;
    Ok(())
}
fn origin(raw: &str) -> Result<String> {
    let u = Url::parse(raw)?;
    let local = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if (u.scheme() != "https" && !(u.scheme() == "http" && local))
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || u.path() != "/"
    {
        return Err("Use an HTTPS gateway origin without credentials, paths or query parameters. HTTP is allowed only on loopback for development.".into());
    }
    Ok(u.origin().ascii_serialization())
}
impl Gateway {
    fn new(explicit: Option<&str>, anonymous: bool) -> Result<Self> {
        let login = load_login()?;
        let raw = explicit
            .map(str::to_owned)
            .or_else(|| env::var("ZNTIL_GATEWAY").ok())
            .or_else(|| login.as_ref().map(|l| l.gateway.clone()))
            .unwrap_or_else(|| "https://zntil.tivq.link".into());
        let origin = origin(&raw)?;
        let token = if anonymous {
            None
        } else {
            env::var("ZNTIL_TOKEN")
                .ok()
                .or_else(|| login.filter(|l| l.gateway == origin).map(|l| l.token))
        };
        Ok(Self {
            origin,
            token,
            client: Client::builder()
                .timeout(Duration::from_secs(20))
                .redirect(Policy::none())
                .build()?,
        })
    }
    fn raw(&self, path: &str, method: &str, body: Option<&Value>) -> Result<(StatusCode, Value)> {
        let mut r = self
            .client
            .request(
                method.parse()?,
                format!("{}/_zntil/admin/{path}", self.origin),
            )
            .header("Origin", &self.origin)
            .header(
                "User-Agent",
                concat!("zntilctl/", env!("CARGO_PKG_VERSION")),
            );
        if let Some(t) = &self.token {
            r = r.bearer_auth(t);
        }
        if let Some(b) = body {
            r = r.json(b);
        }
        let r = r.send()?;
        let status = r.status();
        let mut raw = vec![];
        r.take(2 * 1024 * 1024 + 1).read_to_end(&mut raw)?;
        if raw.len() > 2 * 1024 * 1024 {
            return Err("Gateway response is too large.".into());
        }
        let v = if raw.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&raw)
                .map_err(|_| "Gateway did not return JSON. Check its URL and deployment.")?
        };
        Ok((status, v))
    }
    fn request(&self, path: &str, method: &str, body: Option<&Value>) -> Result<Value> {
        let (status, v) = self.raw(path, method, body)?;
        if !status.is_success() {
            return Err(format!(
                "HTTP {}: {}",
                status.as_u16(),
                v.get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("Request failed")
            )
            .into());
        }
        Ok(v)
    }
    fn state(&self) -> Result<Value> {
        self.request("state", "GET", None)
    }
    fn config(&self) -> Result<Value> {
        let s = self.state()?;
        Ok(json!({"revision":s["revision"],"servers":s["servers"],"proxies":s["proxies"]}))
    }
    fn apply(&self, document: &Value, dry: bool) -> Result<Value> {
        if dry {
            let valid = self.request("validate", "POST", Some(document))?;
            Ok(json!({"dry_run":true,"validation":valid,"config":document}))
        } else {
            self.request("config", "PUT", Some(document))
        }
    }
}
fn read_json(path: &Path) -> Result<Value> {
    let mut raw = vec![];
    if path == Path::new("-") {
        io::stdin().take(512 * 1024 + 1).read_to_end(&mut raw)?;
    } else {
        fs::File::open(path)?
            .take(512 * 1024 + 1)
            .read_to_end(&mut raw)?;
    }
    if raw.len() > 512 * 1024 {
        return Err("Configuration exceeds 512 KiB.".into());
    }
    Ok(serde_json::from_slice(&raw)?)
}
fn print(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}
fn array_mut<'a>(v: &'a mut Value, key: &str) -> Result<&'a mut Vec<Value>> {
    v.get_mut(key)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| format!("Expected {key} array.").into())
}
fn upsert(list: &mut Vec<Value>, entry: Value) {
    if let Some(i) = list.iter().position(|x| x["id"] == entry["id"]) {
        list[i] = entry;
    } else {
        list.push(entry);
    }
}
fn remove(list: &mut Vec<Value>, id: &str) -> Result<()> {
    let n = list.len();
    list.retain(|x| x["id"] != id);
    if list.len() == n {
        return Err(format!("ID {id} was not found.").into());
    }
    Ok(())
}
fn proxy_mut<'a>(doc: &'a mut Value, id: &str) -> Result<&'a mut Value> {
    array_mut(doc, "proxies")?
        .iter_mut()
        .find(|p| p["id"] == id)
        .ok_or_else(|| format!("Proxy {id} was not found.").into())
}
fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let mut cmd = Command::new("open");
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut cmd = Command::new("xdg-open");
    let _ = cmd
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}
fn run(cli: Cli) -> Result<()> {
    if let Commands::Auth(AuthCommand::Login {
        name,
        read_only,
        no_browser,
    }) = &cli.command
    {
        let g = Gateway::new(cli.gateway.as_deref(), true)?;
        let start = g.request(
            "device/start",
            "POST",
            Some(&json!({"name":name,"write":!read_only})),
        )?;
        let url = start["verification_uri"]
            .as_str()
            .ok_or("Missing verification URL")?;
        let verification = Url::parse(url)?;
        if verification.origin().ascii_serialization() != g.origin {
            return Err("Gateway returned a verification URL on another origin.".into());
        }
        eprintln!(
            "Open {url}\nConfirm code {} and requested {} access in the console.\nWaiting for approval…",
            start["user_code"].as_str().unwrap_or(""),
            if *read_only { "read-only" } else { "write" }
        );
        if !no_browser {
            open_browser(url);
        }
        let deadline = Instant::now() + Duration::from_secs(600);
        loop {
            if Instant::now() > deadline {
                return Err("CLI sign-in expired. Start again.".into());
            }
            let (status, v) = g.raw(
                "device/poll",
                "POST",
                Some(&json!({"device_code":start["device_code"]})),
            )?;
            if status == StatusCode::ACCEPTED || status == StatusCode::TOO_MANY_REQUESTS {
                thread::sleep(Duration::from_secs(5));
                continue;
            }
            if !status.is_success() {
                return Err(v["error"]
                    .as_str()
                    .unwrap_or("CLI sign-in failed")
                    .to_owned()
                    .into());
            }
            let login = Login {
                gateway: g.origin.clone(),
                token: v["access_token"]
                    .as_str()
                    .ok_or("Missing access token")?
                    .into(),
                token_id: v["token_id"].as_str().ok_or("Missing token ID")?.into(),
                expires_at: v["expires_at"].as_u64().ok_or("Missing expiry")?,
                scope: v["scope"].as_str().ok_or("Missing scope")?.into(),
            };
            save_login(&login)?;
            return print(
                &json!({"authenticated":true,"gateway":login.gateway,"scope":login.scope,"expires_at":login.expires_at,"token_id":login.token_id}),
            );
        }
    }
    let g = Gateway::new(cli.gateway.as_deref(), false)?;
    if g.token.is_none() {
        return Err("Not signed in. Run zntilctl auth login, or set ZNTIL_TOKEN and ZNTIL_GATEWAY for automation.".into());
    }
    match cli.command {
        Commands::Auth(AuthCommand::Status) => {
            let s = g.state()?;
            print(&json!({"authenticated":true,"gateway":g.origin,"revision":s["revision"]}))
        }
        Commands::Auth(AuthCommand::Logout) => {
            let v = g.request("tokens/revoke-self", "POST", Some(&json!({})))?;
            let path = credential_path()?;
            if let Some(login) = load_login()?
                && login.gateway == g.origin
                && Some(login.token) == g.token
            {
                fs::remove_file(path)?;
            }
            print(&v)
        }
        Commands::Auth(AuthCommand::Login { .. }) => unreachable!(),
        Commands::Status => print(&g.state()?),
        Commands::Config(cmd) => {
            match cmd {
                ConfigCommand::Get { output } => {
                    let v = g.config()?;
                    if let Some(path) = output {
                        fs::write(&path, serde_json::to_vec_pretty(&v)?)?;
                        print(&json!({"written":path,"revision":v["revision"]}))
                    } else {
                        print(&v)
                    }
                }
                ConfigCommand::Validate { file } => {
                    print(&g.request("validate", "POST", Some(&read_json(&file)?))?)
                }
                ConfigCommand::Apply { file } => print(&g.apply(&read_json(&file)?, cli.dry_run)?),
                ConfigCommand::Rollback { revision } => {
                    if cli.dry_run {
                        return Err("Use config get to review history; rollback does not support --dry-run.".into());
                    }
                    let s = g.state()?;
                    print(&g.request(
                        "rollback",
                        "POST",
                        Some(&json!({"revision":revision,"current_revision":s["revision"]})),
                    )?)
                }
            }
        }
        Commands::Servers(cmd) => {
            let mut d = g.config()?;
            match cmd {
                ServerCommand::List => return print(&d["servers"]),
                ServerCommand::Remove { id } => remove(array_mut(&mut d, "servers")?, &id)?,
                ServerCommand::Upsert(a) => {
                    let list = array_mut(&mut d, "servers")?;
                    let mut s=list.iter().find(|s|s["id"]==a.id).cloned().unwrap_or(json!({"id":a.id,"name":a.id,"host":"","port":8080,"tls":false,"origin_token_env":null}));
                    if let Some(v) = a.name {
                        s["name"] = json!(v);
                    }
                    if let Some(v) = a.host {
                        s["host"] = json!(v);
                    }
                    if let Some(v) = a.port {
                        s["port"] = json!(v);
                    }
                    if a.tls {
                        s["tls"] = json!(true);
                    }
                    if a.http {
                        s["tls"] = json!(false);
                    }
                    if let Some(v) = a.origin_token_env {
                        s["origin_token_env"] = json!(v);
                    }
                    upsert(list, s);
                }
            }
            print(&g.apply(&d, cli.dry_run)?)
        }
        Commands::Proxies(cmd) => {
            let mut d = g.config()?;
            match cmd {
                ProxyCommand::List => return print(&d["proxies"]),
                ProxyCommand::Remove { id } => remove(array_mut(&mut d, "proxies")?, &id)?,
                ProxyCommand::Upsert(a) => {
                    let list = array_mut(&mut d, "proxies")?;
                    let mut p=list.iter().find(|p|p["id"]==a.id).cloned().unwrap_or(json!({"id":a.id,"name":a.id,"server_id":"","enabled":true,"route":{"hosts":[],"upstream":"placeholder","rules":[]}}));
                    if let Some(v) = a.name {
                        p["name"] = json!(v);
                    }
                    if let Some(v) = a.server {
                        p["server_id"] = json!(v);
                    }
                    if !a.domain.is_empty() {
                        p["route"]["hosts"] = json!(a.domain);
                    }
                    if let Some(v) = a.upstream_host {
                        p["route"]["upstream_host"] = json!(v);
                    }
                    if a.enable {
                        p["enabled"] = json!(true);
                    }
                    if a.disable {
                        p["enabled"] = json!(false);
                    }
                    for (key, v) in [
                        ("requests_per_second", a.rate),
                        ("burst", a.burst),
                        ("global_requests_per_second", a.global_rate),
                        ("global_burst", a.global_burst),
                    ] {
                        if let Some(v) = v {
                            p["route"][key] = json!(v);
                        }
                    }
                    upsert(list, p);
                }
            }
            print(&g.apply(&d, cli.dry_run)?)
        }
        Commands::Rules(cmd) => {
            let mut d = g.config()?;
            match cmd {
                RuleCommand::List { proxy } => {
                    let rows=d["proxies"].as_array().ok_or("Missing proxies")?.iter().filter(|p|proxy.as_ref().is_none_or(|id|p["id"]==*id)).map(|p|json!({"proxy_id":p["id"],"rules":p["route"].get("rules").cloned().unwrap_or(json!([]))})).collect::<Vec<_>>();
                    return print(&json!(rows));
                }
                RuleCommand::Remove { proxy, id } => {
                    let p = proxy_mut(&mut d, &proxy)?;
                    remove(array_mut(&mut p["route"], "rules")?, &id)?;
                }
                RuleCommand::Upsert(a) => {
                    let p = proxy_mut(&mut d, &a.proxy)?;
                    if p["route"].get("rules").is_none() {
                        p["route"]["rules"] = json!([]);
                    }
                    let list = array_mut(&mut p["route"], "rules")?;
                    let mut r=list.iter().find(|r|r["id"]==a.id).cloned().unwrap_or(json!({"id":a.id,"name":a.id,"path":"/","path_match":"prefix","domains":[],"methods":[],"client_cidrs":[],"action":"block","enabled":true}));
                    if let Some(v) = a.name {
                        r["name"] = json!(v);
                    }
                    if let Some(v) = a.path {
                        r["path"] = json!(v);
                    }
                    if let Some(v) = a.match_type {
                        r["path_match"] = json!(match v {
                            MatchType::Exact => "exact",
                            MatchType::Prefix => "prefix",
                        });
                    }
                    if let Some(v) = a.action {
                        r["action"] = json!(match v {
                            Action::Block => "block",
                            Action::RateLimit => "rate_limit",
                        });
                    }
                    if !a.domain.is_empty() {
                        r["domains"] = json!(a.domain);
                    }
                    if !a.method.is_empty() {
                        r["methods"] = json!(
                            a.method
                                .iter()
                                .map(|s| s.to_ascii_uppercase())
                                .collect::<Vec<_>>()
                        );
                    }
                    if !a.cidr.is_empty() {
                        r["client_cidrs"] = json!(a.cidr);
                    }
                    if r["action"] == "block" {
                        r["requests_per_second"] = Value::Null;
                        r["burst"] = Value::Null;
                    } else {
                        if let Some(v) = a.rate {
                            r["requests_per_second"] = json!(v);
                        }
                        if let Some(v) = a.burst {
                            r["burst"] = json!(v);
                        }
                    }
                    if a.enable {
                        r["enabled"] = json!(true);
                    }
                    if a.disable {
                        r["enabled"] = json!(false);
                    }
                    upsert(list, r);
                }
            }
            print(&g.apply(&d, cli.dry_run)?)
        }
    }
}
fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("{}", json!({"error":e.to_string()}));
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_unsafe_gateway_origins() {
        for s in [
            "http://example.com",
            "https://user:pass@example.com",
            "https://example.com/path",
            "https://example.com/?token=secret",
        ] {
            assert!(origin(s).is_err());
        }
        assert_eq!(
            origin("https://example.com/").unwrap(),
            "https://example.com"
        );
        assert!(origin("http://127.0.0.1:8080").is_ok());
    }
    #[test]
    fn command_contract() {
        assert!(
            Cli::try_parse_from([
                "zntilctl", "rules", "upsert", "--proxy", "web", "--id", "deny", "--domain",
                "app.test", "--path", "/admin", "--action", "block"
            ])
            .is_ok()
        );
    }
}
