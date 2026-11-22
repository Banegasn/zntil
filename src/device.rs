use crate::control::{ApiError, now};
use blake2::{Blake2s256, Digest};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Mutex,
    time::Instant,
};

#[derive(Clone, Serialize, Deserialize)]
struct Credential {
    id: String,
    name: String,
    write: bool,
    created_at: u64,
    expires_at: u64,
    hash: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
struct Credentials {
    generation: [u8; 32],
    tokens: Vec<Credential>,
}
struct Pending {
    code: String,
    name: String,
    write: bool,
    expires_at: u64,
    approved: bool,
    denied: bool,
    last_poll: Option<Instant>,
}
pub struct DeviceAuth {
    file: PathBuf,
    credentials: Mutex<Credentials>,
    pending: Mutex<HashMap<[u8; 32], Pending>>,
}
fn digest(s: &str) -> [u8; 32] {
    Blake2s256::digest(s.as_bytes()).into()
}
fn secret() -> String {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
fn error(code: u16, message: &str) -> ApiError {
    ApiError(code, message.into())
}
impl DeviceAuth {
    pub fn new(directory: &str, key: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file = PathBuf::from(directory).join("credentials.json");
        let generation = digest(key);
        let mut credentials = if file.exists() {
            let raw = fs::read(&file)?;
            if raw.len() > 512 * 1024 {
                return Err("credential store too large".into());
            }
            serde_json::from_slice::<Credentials>(&raw)?
        } else {
            Credentials {
                generation,
                tokens: vec![],
            }
        };
        if credentials.tokens.len() > 128 {
            return Err("credential capacity exceeded".into());
        }
        let rotated = credentials.generation != generation;
        if credentials.generation != generation {
            credentials = Credentials {
                generation,
                tokens: vec![],
            };
        }
        let device = Self {
            file,
            credentials: Mutex::new(credentials),
            pending: Mutex::new(HashMap::new()),
        };
        if rotated {
            device
                .persist(&device.credentials.lock().unwrap())
                .map_err(|e| e.1)?;
        }
        Ok(device)
    }
    fn persist(&self, credentials: &Credentials) -> Result<(), ApiError> {
        let tmp = self.file.with_extension("tmp");
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let result = (|| -> std::io::Result<()> {
            let mut f = opts.open(&tmp)?;
            f.write_all(&serde_json::to_vec(credentials)?)?;
            f.sync_all()?;
            fs::rename(tmp, &self.file)?;
            if let Some(parent) = self.file.parent()
                && let Ok(dir) = fs::File::open(parent)
            {
                let _ = dir.sync_all();
            }
            Ok(())
        })();
        result.map_err(|_| {
            error(
                500,
                "Could not save CLI credentials; no change was applied.",
            )
        })
    }
    pub fn access(&self, token: &str) -> Option<bool> {
        if token.len() != 68 || !token.starts_with("znt_") {
            return None;
        }
        let hash = digest(token);
        self.credentials
            .lock()
            .unwrap()
            .tokens
            .iter()
            .find(|t| t.hash == hash && t.expires_at > now())
            .map(|t| t.write)
    }
    pub fn start(&self, name: &str, write: bool, origin: &str) -> Result<Value, ApiError> {
        if name.trim().is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
            return Err(error(400, "Give the CLI a name of 1–80 characters."));
        }
        let mut pending = self.pending.lock().unwrap();
        pending.retain(|_, p| p.expires_at > now());
        if pending.len() >= 32 {
            return Err(error(503, "Too many pending CLI sign-ins."));
        }
        let device = secret();
        let mut raw = [0u8; 8];
        let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        let code = loop {
            rand::thread_rng().fill_bytes(&mut raw);
            let code = raw
                .iter()
                .map(|b| alphabet[*b as usize % alphabet.len()] as char)
                .collect::<String>();
            if pending.values().all(|p| p.code != code) {
                break code;
            }
        };
        pending.insert(
            digest(&device),
            Pending {
                code: code.clone(),
                name: name.trim().into(),
                write,
                expires_at: now() + 600,
                approved: false,
                denied: false,
                last_poll: None,
            },
        );
        Ok(
            json!({"device_code":device,"user_code":code,"verification_uri":format!("{origin}/console/?device={code}"),"expires_in":600,"interval":5}),
        )
    }
    pub fn pending(&self) -> Value {
        let pending = self.pending.lock().unwrap();
        json!({"pending":pending.values().filter(|p|p.expires_at>now()).map(|p|json!({"user_code":p.code,"name":p.name,"scope":if p.write{"write"}else{"read"},"expires_at":p.expires_at,"approved":p.approved,"denied":p.denied})).collect::<Vec<_>>()})
    }
    pub fn approve(&self, code: &str, approve: bool) -> Result<Value, ApiError> {
        let mut pending = self.pending.lock().unwrap();
        let p = pending
            .values_mut()
            .find(|p| p.code == code && p.expires_at > now())
            .ok_or_else(|| error(404, "CLI sign-in code was not found or has expired."))?;
        if p.approved || p.denied {
            return Err(error(409, "This sign-in was already decided."));
        }
        p.approved = approve;
        p.denied = !approve;
        Ok(json!({"approved":approve}))
    }
    pub fn poll(&self, device: &str) -> Result<(u16, Value), ApiError> {
        if device.len() != 64 {
            return Err(error(400, "Invalid device code."));
        }
        let key = digest(device);
        let mut pending = self.pending.lock().unwrap();
        pending.retain(|_, p| p.expires_at > now());
        let p = pending
            .get_mut(&key)
            .ok_or_else(|| error(400, "Device code expired or was already consumed."))?;
        if p.last_poll.is_some_and(|last| last.elapsed().as_secs() < 2) {
            return Err(error(429, "slow_down"));
        }
        p.last_poll = Some(Instant::now());
        if p.denied {
            pending.remove(&key);
            return Err(error(403, "CLI sign-in was denied."));
        }
        if !p.approved {
            return Ok((202, json!({"status":"pending"})));
        }
        let token = format!("znt_{}", secret());
        let mut stored = self.credentials.lock().unwrap();
        let mut next = stored.clone();
        next.tokens.retain(|t| t.expires_at > now());
        if next.tokens.len() >= 128 {
            return Err(error(
                503,
                "Revoke an old CLI credential before creating another.",
            ));
        }
        let entry = Credential {
            id: secret()[..16].into(),
            name: p.name.clone(),
            write: p.write,
            created_at: now(),
            expires_at: now() + 30 * 24 * 3600,
            hash: digest(&token),
        };
        let response = json!({"access_token":token,"token_type":"Bearer","expires_at":entry.expires_at,"token_id":entry.id,"scope":if entry.write{"write"}else{"read"}});
        next.tokens.push(entry);
        self.persist(&next)?;
        *stored = next;
        pending.remove(&key);
        Ok((200, response))
    }
    pub fn list(&self) -> Value {
        json!({"tokens":self.credentials.lock().unwrap().tokens.iter().filter(|t|t.expires_at>now()).map(|t|json!({"id":t.id,"name":t.name,"scope":if t.write{"write"}else{"read"},"created_at":t.created_at,"expires_at":t.expires_at})).collect::<Vec<_>>()})
    }
    pub fn revoke(&self, id: &str) -> Result<Value, ApiError> {
        let mut stored = self.credentials.lock().unwrap();
        let mut next = stored.clone();
        next.tokens.retain(|t| t.id != id);
        if next.tokens.len() == stored.tokens.len() {
            return Err(error(404, "CLI credential was not found."));
        }
        self.persist(&next)?;
        *stored = next;
        Ok(json!({"revoked":true}))
    }
    pub fn revoke_self(&self, token: &str) -> Result<Value, ApiError> {
        let hash = digest(token);
        let id = self
            .credentials
            .lock()
            .unwrap()
            .tokens
            .iter()
            .find(|t| t.hash == hash)
            .map(|t| t.id.clone())
            .ok_or_else(|| error(401, "Unknown CLI credential."))?;
        self.revoke(&id)
    }
}
