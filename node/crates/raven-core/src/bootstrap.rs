//! Bootstrap peer configuration (§30).
//!
//! Raven-provided defaults are optional, empty, and off unless the user opts
//! in — a user can start with only manually supplied multiaddrs / host:port
//! peers. Bootstrap peers are untrusted relays for dial hints only (no
//! identity authority, no plaintext).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

/// Bootstrap / dial-hint configuration (no secrets). The default is all empty
/// and off: serverless V1 does not require Raven-owned nodes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapConfig {
    /// When false, ignore `raven_defaults` entirely. Opt-in (default false
    /// since 2026-10, decision D1): use the Raven-shipped list, which is empty
    /// in every build. A file that holds an explicit `true` keeps it.
    #[serde(default)]
    pub use_raven_defaults: bool,
    /// Optional Raven-shipped multiaddrs (may be empty — not required).
    #[serde(default)]
    pub raven_defaults: Vec<String>,
    /// User-supplied bootstrap multiaddrs (community or self-hosted).
    #[serde(default)]
    pub custom: Vec<String>,
    /// Explicit manual peers for direct dial (proves no Raven-owned dependency).
    #[serde(default)]
    pub manual_peers: Vec<String>,
}

impl BootstrapConfig {
    /// Effective dial targets: manual + custom + (optional empty Raven defaults).
    pub fn effective_peers(&self) -> Vec<String> {
        let mut out = Vec::new();
        for p in &self.manual_peers {
            push_unique(&mut out, p);
        }
        for p in &self.custom {
            push_unique(&mut out, p);
        }
        if self.use_raven_defaults {
            for p in &self.raven_defaults {
                push_unique(&mut out, p);
            }
        }
        out
    }

    /// True when startup can proceed without any Raven-owned bootstrap entry.
    pub fn manual_peer_only_ok(&self) -> bool {
        !self.manual_peers.is_empty()
            && (self.raven_defaults.is_empty() || !self.use_raven_defaults)
    }

    pub fn add_custom(&mut self, multiaddr: impl Into<String>) {
        let s = multiaddr.into();
        if !self.custom.iter().any(|x| x == &s) {
            self.custom.push(s);
        }
    }

    pub fn remove_raven_defaults(&mut self) {
        self.use_raven_defaults = false;
        self.raven_defaults.clear();
    }

    /// Applied when `bootstrap.json` exists but cannot be read or parsed:
    /// no dial hints at all, and Raven defaults off (a user who opted out of
    /// Raven-provided peers must not be silently opted back in).
    pub fn fail_closed() -> Self {
        Self {
            use_raven_defaults: false,
            raven_defaults: Vec::new(),
            custom: Vec::new(),
            manual_peers: Vec::new(),
        }
    }
}

fn push_unique(out: &mut Vec<String>, p: &str) {
    if !out.iter().any(|x| x == p) {
        out.push(p.to_string());
    }
}

#[derive(Error, Debug)]
pub enum BootstrapError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("write: {0}")]
    Write(String),
    /// Sealed (privacy pack PP.5), and this process cannot open it: the
    /// at-rest key is not loaded, or the bytes do not open. Never read as
    /// "no peers" for a write, never moved aside.
    #[error("sealed: {0}")]
    Sealed(String),
}

/// The file in the data dir: plain until the profile has an identity (it is
/// one of the first-install inert files), RMS1 kind 20 once the profile is
/// sealed (PP.5); readers accept both.
pub const BOOTSTRAP_FILE: &str = "bootstrap.json";

pub fn bootstrap_path(data_dir: &Path) -> PathBuf {
    data_dir.join(BOOTSTRAP_FILE)
}

/// Missing file → [`BootstrapConfig::default`]. Unreadable or corrupt → error.
pub fn try_load_bootstrap(data_dir: &Path) -> Result<BootstrapConfig, BootstrapError> {
    let path = bootstrap_path(data_dir);
    let raw = match crate::at_rest::load_bytes(data_dir, &path, crate::at_rest::Kind::Bootstrap) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Ok(BootstrapConfig::default()),
        Err(crate::at_rest::AtRestError::Io(e)) => return Err(std::io::Error::other(e).into()),
        Err(e) => return Err(BootstrapError::Sealed(e.to_string())),
    };
    Ok(serde_json::from_slice(&raw)?)
}

static CORRUPT_BOOTSTRAP_WARNED: AtomicBool = AtomicBool::new(false);

/// Never fails open: a corrupt or unreadable file yields
/// [`BootstrapConfig::fail_closed`] (warned once per process).
pub fn load_bootstrap(data_dir: &Path) -> BootstrapConfig {
    match try_load_bootstrap(data_dir) {
        Ok(cfg) => cfg,
        Err(e) => {
            if !CORRUPT_BOOTSTRAP_WARNED.swap(true, Ordering::Relaxed) {
                eprintln!("raven: bootstrap.json unusable ({e}); using no bootstrap peers");
            }
            BootstrapConfig::fail_closed()
        }
    }
}

/// Where [`save_bootstrap`] keeps a `bootstrap.json` it found unparsable.
pub fn corrupt_bootstrap_backup_path(data_dir: &Path) -> PathBuf {
    data_dir.join(BOOTSTRAP_CORRUPT_FILE)
}

/// [`corrupt_bootstrap_backup_path`]'s name.
pub const BOOTSTRAP_CORRUPT_FILE: &str = "bootstrap.json.corrupt";

/// Atomic replace (temp + fsync + rename, owner-only); never a torn file.
/// Under the file's writer lock; sealed (RMS1) in a sealed profile, which a
/// profile is only once it has an identity, so a write before the identity
/// stays plain and the next migration seals it.
///
/// Read-modify-write callers start from [`load_bootstrap`], which turns a
/// corrupt or hand-edited file into an *empty* fail-closed config; saving that
/// would silently replace the user's peers with just the new entry. So an
/// existing file that does not parse is first moved aside to
/// [`corrupt_bootstrap_backup_path`] (kept, never deleted; sealed in place in
/// a sealed profile), and one that cannot even be read,
/// or is sealed and does not open, is not overwritten at all. A missing or
/// valid file is simply replaced.
pub fn save_bootstrap(data_dir: &Path, cfg: &BootstrapConfig) -> Result<(), BootstrapError> {
    let raw = serde_json::to_string_pretty(cfg)?;
    let lock = crate::at_rest::lock_file(
        data_dir,
        &bootstrap_path(data_dir),
        crate::at_rest::Kind::Bootstrap,
    )
    .map_err(|e| BootstrapError::Write(e.to_string()))?;
    match try_load_bootstrap(data_dir) {
        Ok(_) => {}
        Err(BootstrapError::Json(e)) => {
            let backup = corrupt_bootstrap_backup_path(data_dir);
            std::fs::rename(bootstrap_path(data_dir), &backup).map_err(|rename_err| {
                BootstrapError::Write(format!(
                    "bootstrap.json is unparsable ({e}) and could not be saved to {}: {rename_err}",
                    backup.display()
                ))
            })?;
            eprintln!(
                "raven: bootstrap.json was unparsable ({e}); the old file was kept as {}",
                backup.display()
            );
            // A plain copy holds the user's peers in clear: in a sealed
            // profile it is sealed at once (the lock held is its lock too;
            // otherwise the next migration does it).
            if crate::privacy::mode(data_dir) == crate::at_rest::Mode::Sealed {
                let _ = crate::at_rest::migrate_file_held(
                    data_dir,
                    &backup,
                    crate::at_rest::Kind::Bootstrap,
                );
            }
        }
        Err(e) => {
            return Err(BootstrapError::Write(format!(
                "bootstrap.json is unreadable ({e}); not overwriting it"
            )));
        }
    }
    lock.store_bytes(raw.as_bytes())
        .map_err(|e| BootstrapError::Write(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn manual_peer_only_without_raven() {
        let mut cfg = BootstrapConfig::default();
        assert!(cfg.raven_defaults.is_empty());
        cfg.manual_peers.push("/ip4/127.0.0.1/tcp/4001".into());
        assert!(cfg.manual_peer_only_ok());
        assert_eq!(cfg.effective_peers().len(), 1);
    }

    #[test]
    fn disable_raven_defaults() {
        let mut cfg = BootstrapConfig {
            use_raven_defaults: true,
            raven_defaults: vec!["/dnsaddr/bootstrap.example".into()],
            custom: vec![],
            manual_peers: vec!["/ip4/10.0.0.1/tcp/9".into()],
        };
        assert!(!cfg.manual_peer_only_ok());
        cfg.remove_raven_defaults();
        assert!(cfg.manual_peer_only_ok());
        assert_eq!(
            cfg.effective_peers(),
            vec!["/ip4/10.0.0.1/tcp/9".to_string()]
        );
    }

    #[test]
    fn roundtrip_file() {
        let dir = tempdir().unwrap();
        let mut cfg = BootstrapConfig::default();
        cfg.add_custom("/ip4/192.0.2.1/tcp/4001");
        cfg.manual_peers.push("127.0.0.1:9000".into());
        save_bootstrap(dir.path(), &cfg).unwrap();
        let loaded = load_bootstrap(dir.path());
        assert_eq!(loaded.custom.len(), 1);
        assert_eq!(loaded.manual_peers.len(), 1);
    }

    /// Raven-provided peers are opt-in: the default, an empty file and a
    /// missing file all leave them off.
    #[test]
    fn raven_defaults_are_opt_in() {
        let dir = tempdir().unwrap();
        let empty: BootstrapConfig = serde_json::from_str("{}").unwrap();
        for cfg in [
            BootstrapConfig::default(),
            empty,
            try_load_bootstrap(dir.path()).unwrap(),
        ] {
            assert!(!cfg.use_raven_defaults, "{cfg:?}");
            assert!(cfg.effective_peers().is_empty(), "{cfg:?}");
        }
        assert_eq!(BootstrapConfig::default(), BootstrapConfig::fail_closed());
    }

    /// No migration: a file written while the default was true (old
    /// `init-bootstrap` / `add-bootstrap`) keeps its explicit opt-in.
    #[test]
    fn an_explicit_opt_in_is_kept() {
        let raw = "{\"use_raven_defaults\":true,\"raven_defaults\":[\"/dns/x\"]}";
        let cfg: BootstrapConfig = serde_json::from_str(raw).unwrap();
        assert!(cfg.use_raven_defaults);
        assert_eq!(cfg.effective_peers(), vec!["/dns/x".to_string()]);

        let dir = tempdir().unwrap();
        std::fs::write(bootstrap_path(dir.path()), raw).unwrap();
        let mut cfg = load_bootstrap(dir.path());
        cfg.add_custom("/ip4/192.0.2.1/tcp/4001");
        save_bootstrap(dir.path(), &cfg).unwrap();
        let loaded = try_load_bootstrap(dir.path()).unwrap();
        assert!(loaded.use_raven_defaults);
        assert!(loaded.effective_peers().contains(&"/dns/x".to_string()));
    }

    /// A Raven list without the flag is ignored: only the user's own peers
    /// are dialled.
    #[test]
    fn a_list_without_the_flag_is_ignored() {
        let cfg: BootstrapConfig = serde_json::from_str(
            "{\"raven_defaults\":[\"/dns/x\"],\"manual_peers\":[\"10.0.0.1:9\"]}",
        )
        .unwrap();
        assert!(!cfg.use_raven_defaults);
        assert_eq!(cfg.effective_peers(), cfg.manual_peers);
        assert!(cfg.manual_peer_only_ok());
    }

    #[test]
    fn missing_file_uses_defaults() {
        let dir = tempdir().unwrap();
        assert_eq!(
            try_load_bootstrap(dir.path()).unwrap(),
            BootstrapConfig::default()
        );
    }

    #[test]
    fn corrupt_or_truncated_file_fails_closed() {
        // A torn write used to revert to defaults (use_raven_defaults=true),
        // silently opting a user back into Raven-provided peers.
        let dir = tempdir().unwrap();
        for raw in ["", "{\"use_raven_defaults\": fa", "null"] {
            std::fs::write(bootstrap_path(dir.path()), raw).unwrap();
            assert!(try_load_bootstrap(dir.path()).is_err(), "{raw:?}");
            let loaded = load_bootstrap(dir.path());
            assert_eq!(loaded, BootstrapConfig::fail_closed(), "{raw:?}");
            assert!(!loaded.use_raven_defaults);
            assert!(loaded.effective_peers().is_empty());
        }
    }

    /// Read-modify-write callers load with the fail-closed `load_bootstrap`
    /// (empty on a parse error). Saving that must not silently destroy the
    /// user's existing peers: the unparsable file is kept.
    #[test]
    fn saving_over_an_unparsable_file_keeps_the_original() {
        let dir = tempdir().unwrap();
        let original =
            "{\"manual_peers\": [\"10.0.0.1:9\",], \"custom\": [\"/ip4/1.1.1.1/tcp/1\"]}";
        std::fs::write(bootstrap_path(dir.path()), original).unwrap();

        let mut cfg = load_bootstrap(dir.path());
        assert_eq!(cfg, BootstrapConfig::fail_closed());
        cfg.add_custom("/ip4/1.2.3.4/tcp/4001");
        save_bootstrap(dir.path(), &cfg).unwrap();

        assert_eq!(try_load_bootstrap(dir.path()).unwrap(), cfg);
        assert_eq!(
            std::fs::read_to_string(corrupt_bootstrap_backup_path(dir.path())).unwrap(),
            original
        );
        // A later valid save does not touch the kept backup.
        cfg.add_custom("/ip4/5.6.7.8/tcp/4001");
        save_bootstrap(dir.path(), &cfg).unwrap();
        assert_eq!(
            std::fs::read_to_string(corrupt_bootstrap_backup_path(dir.path())).unwrap(),
            original
        );
    }

    #[test]
    fn saving_does_not_overwrite_an_unreadable_file() {
        let dir = tempdir().unwrap();
        // A directory where the file belongs: read fails with an I/O error that
        // is not "not found", so the (unknowable) contents must not be replaced.
        std::fs::create_dir(bootstrap_path(dir.path())).unwrap();
        let err = save_bootstrap(dir.path(), &BootstrapConfig::default()).unwrap_err();
        assert!(matches!(err, BootstrapError::Write(_)), "{err}");
        assert!(bootstrap_path(dir.path()).is_dir());
    }

    #[test]
    fn save_is_atomic_and_owner_only() {
        let dir = tempdir().unwrap();
        let path = bootstrap_path(dir.path());
        std::fs::write(&path, "{\"custom\": [").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let mut cfg = BootstrapConfig::fail_closed();
        cfg.manual_peers.push("127.0.0.1:9000".into());
        save_bootstrap(dir.path(), &cfg).unwrap();
        assert_eq!(try_load_bootstrap(dir.path()).unwrap(), cfg);
        // No temp file is left behind; the torn original is kept aside
        // (beside the writer's empty lock database, privacy pack PP.5).
        let mut names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|name| !name.to_string_lossy().ends_with(".lock.sqlite"))
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                std::ffi::OsString::from("bootstrap.json"),
                std::ffi::OsString::from("bootstrap.json.corrupt"),
            ]
        );
        assert_eq!(
            std::fs::read_to_string(corrupt_bootstrap_backup_path(dir.path())).unwrap(),
            "{\"custom\": ["
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
