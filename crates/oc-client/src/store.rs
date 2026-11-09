//! Encrypted on-disk state.
//!
//! File layout: `magic(8) || salt(16) || nonce(24) || ciphertext`.
//! The JSON state is sealed with XChaCha20-Poly1305; the key is derived from
//! the user passphrase with Argon2id.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use oc_core::aead;
use oc_core::random_array;
use zeroize::Zeroize;

use crate::state::ClientState;
use crate::{Error, Result};

const MAGIC: &[u8; 8] = b"OCSTATE1";
const SALT_LEN: usize = 16;
const AAD: &[u8] = b"openchat/state/v1";
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + aead::NONCE_LEN;
const STATE_FILE: &str = "state.enc";

/// Argon2id cost parameters (OWASP baseline).
const ARGON_M_COST: u32 = 19_456;
const ARGON_T_COST: u32 = 2;
const ARGON_P_COST: u32 = 1;

/// Encrypted state file handle.
///
/// Holds an exclusive lock on `<dir>/.lock` for its whole lifetime so
/// two processes cannot load the same snapshot and diverge the ratchet
/// (audit H24).
pub struct StateStore {
    path: PathBuf,
    salt: [u8; SALT_LEN],
    key: [u8; 32],
    _lock: fs::File,
}

/// Acquire the per-state-directory lock (fail fast on contention).
fn acquire_lock(dir: &Path) -> Result<fs::File> {
    use fs2::FileExt;
    fs::create_dir_all(dir)?;
    let lock_path = dir.join(".lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| Error::State(format!("cannot open state lock: {error}")))?;
    file.try_lock_exclusive()
        .map_err(|_| Error::State("state is already open in another process".into()))?;
    Ok(file)
}

impl core::fmt::Debug for StateStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StateStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Drop for StateStore {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl StateStore {
    /// Path of the state file inside `dir`.
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(STATE_FILE)
    }

    /// Whether a state file exists in `dir`.
    pub fn exists(dir: &Path) -> bool {
        Self::path_in(dir).is_file()
    }

    /// Create a new store with a fresh random salt.
    ///
    /// Fails if a state file already exists, so a mistyped command cannot
    /// destroy an identity.
    pub fn create(dir: &Path, passphrase: &str) -> Result<Self> {
        let path = Self::path_in(dir);
        if path.exists() {
            // No full path in errors (audit M-U12): error output lands
            // on screens and in logs.
            return Err(Error::State("state already exists".into()));
        }

        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }

        let salt = random_array::<SALT_LEN>();
        let key = derive_key(passphrase, &salt)?;
        let lock = acquire_lock(dir)?;
        Ok(Self {
            path,
            salt,
            key,
            _lock: lock,
        })
    }

    /// Open an existing encrypted state file.
    pub fn open(dir: &Path, passphrase: &str) -> Result<Self> {
        let path = Self::path_in(dir);
        let mut file = fs::File::open(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::State("not initialized (state.enc missing)".into())
            } else {
                Error::Io(error)
            }
        })?;

        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        if contents.len() < HEADER_LEN || &contents[..MAGIC.len()] != MAGIC {
            return Err(Error::State("not an OpenChat state file".into()));
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&contents[MAGIC.len()..MAGIC.len() + SALT_LEN]);
        let key = derive_key(passphrase, &salt)?;
        let lock = acquire_lock(dir)?;

        Ok(Self {
            path,
            salt,
            key,
            _lock: lock,
        })
    }

    /// Encrypted state file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Decrypt and parse the state.
    pub fn load(&self) -> Result<ClientState> {
        let contents = fs::read(&self.path)?;
        if contents.len() < HEADER_LEN || &contents[..MAGIC.len()] != MAGIC {
            return Err(Error::State("not an OpenChat state file".into()));
        }

        let salt_offset = MAGIC.len();
        let nonce_offset = salt_offset + SALT_LEN;
        let mut nonce = [0u8; aead::NONCE_LEN];
        nonce.copy_from_slice(&contents[nonce_offset..HEADER_LEN]);

        // The salt in the header must match the one the key was derived from.
        if contents[salt_offset..nonce_offset] != self.salt {
            return Err(Error::BadPassphrase);
        }

        let plaintext = aead::decrypt(&self.key, &nonce, AAD, &contents[HEADER_LEN..])
            .map_err(|_| Error::BadPassphrase)?;
        let state: ClientState = serde_json::from_slice(&plaintext)?;
        state.validate()?;
        Ok(state)
    }

    /// Encrypt and atomically replace the state file.
    pub fn save(&self, state: &ClientState) -> Result<()> {
        state.validate()?;
        let plaintext = serde_json::to_vec(state)?;
        let nonce = random_array::<{ aead::NONCE_LEN }>();
        let ciphertext = aead::encrypt(&self.key, &nonce, AAD, &plaintext)
            .map_err(|_| Error::State("state encryption failed".into()))?;
        // Scrub the plaintext copy after sealing (audit L1).
        let _plaintext_guard = zeroize::Zeroizing::new(plaintext);

        let mut contents = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        contents.extend_from_slice(MAGIC);
        contents.extend_from_slice(&self.salt);
        contents.extend_from_slice(&nonce);
        contents.extend_from_slice(&ciphertext);

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Random-suffixed temp name opened with O_EXCL so a symlink at
        // the predictable `state.enc.tmp` path cannot redirect the
        // write (audit M-L8).
        let temp = self
            .path
            .with_extension(format!("enc.{}.tmp", hex::encode(random_array::<8>())));
        write_private_new(&temp, &contents)?;
        fs::rename(&temp, &self.path)?;
        // fsync file + directory so a crash cannot lose the rename.
        if let Ok(file) = fs::File::open(&self.path) {
            let _ = file.sync_all();
        }
        if let Some(parent) = self.path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }
}

fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; 32]> {
    let params = argon2::Params::new(ARGON_M_COST, ARGON_T_COST, ARGON_P_COST, Some(32))
        .map_err(|_| Error::State("invalid Argon2 parameters".into()))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| Error::State("key derivation failed".into()))?;
    Ok(key)
}

/// Write with `O_CREAT | O_EXCL`: fails if the (random) path exists,
/// so no symlink at a predictable temp name can redirect the write.
fn write_private_new(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn second_open_fails_while_locked() {
        let dir = tempdir();
        let store = StateStore::create(dir.path(), "passphrase").unwrap();
        store
            .save(&ClientState::generate(Vec::new()).unwrap())
            .unwrap();
        assert!(StateStore::open(dir.path(), "passphrase").is_err());
        drop(store);
        assert!(StateStore::open(dir.path(), "passphrase").is_ok());
    }

    #[test]
    fn state_survives_restart() {
        let dir = tempdir();
        let store = StateStore::create(dir.path(), "correct horse battery staple").unwrap();
        let state = ClientState::generate(vec!["https://relay.example".into()]).unwrap();
        store.save(&state).unwrap();
        drop(store); // release the state lock before reopening

        let reopened = StateStore::open(dir.path(), "correct horse battery staple").unwrap();
        let loaded = reopened.load().unwrap();
        assert_eq!(loaded.peer_id().unwrap(), state.peer_id().unwrap());
        assert_eq!(loaded.relays, state.relays);
    }

    #[test]
    fn wrong_passphrase_fails_cleanly() {
        let dir = tempdir();
        let store = StateStore::create(dir.path(), "right").unwrap();
        let state = ClientState::generate(Vec::new()).unwrap();
        store.save(&state).unwrap();
        drop(store); // release the state lock before reopening

        let wrong = StateStore::open(dir.path(), "wrong").unwrap();
        assert!(matches!(wrong.load(), Err(Error::BadPassphrase)));
    }

    #[test]
    fn corruption_is_detected() {
        let dir = tempdir();
        let store = StateStore::create(dir.path(), "passphrase").unwrap();
        store
            .save(&ClientState::generate(Vec::new()).unwrap())
            .unwrap();

        let path = store.path().to_path_buf();
        drop(store); // release the state lock before reopening
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, bytes).unwrap();

        let store = StateStore::open(dir.path(), "passphrase").unwrap();
        assert!(matches!(store.load(), Err(Error::BadPassphrase)));
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let dir = tempdir();
        let store = StateStore::create(dir.path(), "passphrase").unwrap();
        store
            .save(&ClientState::generate(Vec::new()).unwrap())
            .unwrap();
        // A second create fails (state exists and the lock is held).
        assert!(StateStore::create(dir.path(), "passphrase").is_err());
        drop(store);
    }

    #[cfg(unix)]
    #[test]
    fn state_file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir();
        let store = StateStore::create(dir.path(), "passphrase").unwrap();
        store
            .save(&ClientState::generate(Vec::new()).unwrap())
            .unwrap();
        let mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
