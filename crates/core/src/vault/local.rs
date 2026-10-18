//! The vault in the app's own database (SS-04, AP-06). See the module docs in `vault/mod.rs`.

use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;
use tokio::time::{Instant, MissedTickBehavior};
use uuid::Uuid;

use super::crypto::{self, KdfParams, Key, SALT_LEN};
use super::protector::KeyProtector;
use super::{
    check_master_password, check_secret, clean_label, SecretId, SecretKind, SecretMeta, SecretString, UnlockMethod,
    Vault, VaultInfo, VaultStatus,
};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::locks;
use crate::store::{Store, VaultMetaRow};

/// SS-04: the vault locks after this long without use.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub struct VaultOptions {
    /// Used when a master key is made: at setup and at a password change. Unlocking uses the
    /// parameters saved with the vault.
    pub kdf: KdfParams,
    pub idle_timeout: Duration,
}

impl Default for VaultOptions {
    fn default() -> Self {
        Self {
            kdf: KdfParams::DEFAULT,
            idle_timeout: IDLE_TIMEOUT,
        }
    }
}

impl VaultOptions {
    /// Fast key derivation for tests. Never in the app.
    #[cfg(any(test, feature = "fakes"))]
    pub fn insecure_fast() -> Self {
        Self {
            kdf: KdfParams::INSECURE_FAST,
            idle_timeout: IDLE_TIMEOUT,
        }
    }
}

/// The data key while the vault is unlocked.
struct OpenKey {
    key: Key,
    last_used: Instant,
}

struct State {
    /// `None` until the vault is set up; then whether the Windows login unlocks it.
    windows_login: Option<bool>,
    open: Option<OpenKey>,
}

struct Inner {
    store: Store,
    ctx: Context,
    protector: Arc<dyn KeyProtector>,
    options: VaultOptions,
    state: Mutex<State>,
    status: watch::Sender<VaultStatus>,
}

/// AAD of the master-key copy of the data key: it belongs to this workspace's vault.
fn key_aad(ctx: &Context) -> Vec<u8> {
    format!("remotely/vault-key/v1/{}", ctx.workspace_id).into_bytes()
}

fn dpapi_entropy(ctx: &Context) -> Vec<u8> {
    format!("remotely/vault-dpapi/v1/{}", ctx.workspace_id).into_bytes()
}

/// AAD of an item: its ciphertext only decrypts in its own row, under its own kind.
fn item_aad(ctx: &Context, id: SecretId, kind: SecretKind) -> Vec<u8> {
    format!("remotely/vault-item/v1/{}/{id}/{}", ctx.workspace_id, kind.as_str()).into_bytes()
}

/// Runs slow or blocking work (Argon2id, DPAPI) off the async threads.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| CoreError::Vault(format!("the vault task stopped: {err}")))?
}

impl Inner {
    fn status_of(&self, state: &State) -> VaultStatus {
        match (state.windows_login, &state.open) {
            (None, _) => VaultStatus::NotSetUp,
            (Some(_), None) => VaultStatus::Locked,
            (Some(_), Some(_)) => VaultStatus::Unlocked,
        }
    }

    fn publish(&self, state: &State) {
        let status = self.status_of(state);
        self.status.send_if_modified(|current| {
            let changed = *current != status;
            *current = status;
            changed
        });
    }

    /// Drops the key (zeroizing it) once it has gone unused for the idle timeout.
    fn expire_if_idle(&self, state: &mut State) {
        if state
            .open
            .as_ref()
            .is_some_and(|open| open.last_used.elapsed() >= self.options.idle_timeout)
        {
            state.open = None;
            tracing::info!("the vault locked after being idle");
            self.publish(state);
        }
    }

    fn lock_if_idle(&self) {
        let mut state = locks::lock(&self.state);
        self.expire_if_idle(&mut state);
    }

    /// Runs `f` with the data key, counting as use. Short and synchronous: no await under the lock.
    fn with_key<T>(&self, f: impl FnOnce(&Key) -> Result<T>) -> Result<T> {
        let mut state = locks::lock(&self.state);
        self.expire_if_idle(&mut state);
        if state.windows_login.is_none() {
            return Err(CoreError::VaultNotSetUp);
        }
        let open = state.open.as_mut().ok_or(CoreError::VaultLocked)?;
        open.last_used = Instant::now();
        f(&open.key)
    }

    fn open_with(&self, key: Key, windows_login: bool) {
        let mut state = locks::lock(&self.state);
        state.windows_login = Some(windows_login);
        state.open = Some(OpenKey {
            key,
            last_used: Instant::now(),
        });
        self.publish(&state);
    }

    fn check_ctx(&self, ctx: &Context) -> Result<()> {
        if ctx.workspace_id == self.ctx.workspace_id {
            Ok(())
        } else {
            Err(CoreError::InvalidInput(
                "This vault belongs to another workspace.".into(),
            ))
        }
    }

    async fn meta(&self) -> Result<VaultMetaRow> {
        self.store.vault_meta(&self.ctx).await?.ok_or(CoreError::VaultNotSetUp)
    }

    /// The data key, if `password` is the master password.
    async fn unwrap_with_password(&self, meta: &VaultMetaRow, password: &SecretString) -> Result<Option<Key>> {
        if password.is_empty() {
            return Ok(None);
        }
        let password = password.clone();
        let salt = meta.kdf_salt.clone();
        let params = meta.kdf_params;
        let wrapped = meta.wrapped_key.clone();
        let aad = key_aad(&self.ctx);
        blocking(move || {
            let kek = crypto::derive(&password, &salt, &params)?;
            crypto::unwrap(&kek, &wrapped, &aad)
        })
        .await
    }

    /// A new salt and master key for `password`, and the data key wrapped by it.
    async fn wrap_with_password(&self, key: &Key, password: SecretString) -> Result<([u8; SALT_LEN], Vec<u8>)> {
        let mut salt = [0u8; SALT_LEN];
        crypto::random(&mut salt)?;
        let params = self.options.kdf;
        let copy = Key::from_bytes(key.as_bytes())?;
        let aad = key_aad(&self.ctx);
        let wrapped = blocking(move || {
            let kek = crypto::derive(&password, &salt, &params)?;
            crypto::wrap(&kek, &copy, &aad)
        })
        .await?;
        Ok((salt, wrapped))
    }

    async fn protect_with_dpapi(&self, key: &Key) -> Result<Vec<u8>> {
        if !self.protector.available() {
            return Err(CoreError::InvalidInput(
                "The Windows login can't protect the vault on this machine; use the vault password.".into(),
            ));
        }
        let protector = Arc::clone(&self.protector);
        let copy = Key::from_bytes(key.as_bytes())?;
        let entropy = dpapi_entropy(&self.ctx);
        blocking(move || protector.protect(copy.as_bytes(), &entropy)).await
    }
}

/// The vault kept in the `vault_meta` and `vault_items` tables, for one workspace.
pub struct LocalVault {
    inner: Arc<Inner>,
}

impl LocalVault {
    /// Reads whether the workspace has a vault yet. Starts locked, and starts the idle check.
    pub async fn open(
        store: Store,
        ctx: Context,
        protector: Arc<dyn KeyProtector>,
        options: VaultOptions,
    ) -> Result<Self> {
        let meta = store.vault_meta(&ctx).await?;
        let state = State {
            windows_login: meta.map(|m| m.dpapi_key.is_some()),
            open: None,
        };
        let initial = if state.windows_login.is_some() {
            VaultStatus::Locked
        } else {
            VaultStatus::NotSetUp
        };
        let inner = Arc::new(Inner {
            store,
            ctx,
            protector,
            options,
            state: Mutex::new(state),
            status: watch::channel(initial).0,
        });
        spawn_idle_check(Arc::downgrade(&inner), inner.options.idle_timeout);
        Ok(Self { inner })
    }
}

/// Locks the vault on time even when nothing touches it, so the key leaves memory and the UI hears
/// of it. Stops once the vault is dropped.
fn spawn_idle_check(inner: Weak<Inner>, idle_timeout: Duration) {
    let every = (idle_timeout / 4).clamp(Duration::from_millis(100), Duration::from_secs(30));
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(inner) = inner.upgrade() else { break };
            inner.lock_if_idle();
        }
    });
}

#[async_trait]
impl Vault for LocalVault {
    fn info(&self) -> VaultInfo {
        let inner = &self.inner;
        let mut state = locks::lock(&inner.state);
        inner.expire_if_idle(&mut state);
        VaultInfo {
            status: inner.status_of(&state),
            windows_login: state.windows_login.unwrap_or(false),
            windows_login_available: inner.protector.available(),
            idle_lock_minutes: inner.options.idle_timeout.as_secs().div_ceil(60),
        }
    }

    fn watch(&self) -> watch::Receiver<VaultStatus> {
        self.inner.status.subscribe()
    }

    async fn setup(&self, ctx: &Context, password: SecretString, windows_login: bool) -> Result<()> {
        let inner = &self.inner;
        inner.check_ctx(ctx)?;
        let known = locks::lock(&inner.state).windows_login.is_some();
        if known || inner.store.vault_meta(ctx).await?.is_some() {
            return Err(CoreError::InvalidInput("The vault is already set up.".into()));
        }
        check_master_password(&password)?;
        let key = Key::generate()?;
        let dpapi_key = if windows_login {
            Some(inner.protect_with_dpapi(&key).await?)
        } else {
            None
        };
        let (salt, wrapped) = inner.wrap_with_password(&key, password).await?;
        inner
            .store
            .insert_vault_meta(ctx, &salt, &inner.options.kdf, &wrapped, dpapi_key.as_deref())
            .await?;
        inner.open_with(key, windows_login);
        Ok(())
    }

    async fn unlock(&self, method: UnlockMethod) -> Result<()> {
        let inner = &self.inner;
        let meta = inner.meta().await?;
        let windows_login = meta.dpapi_key.is_some();
        let key = match method {
            UnlockMethod::WindowsLogin => {
                let Some(blob) = meta.dpapi_key else {
                    return Err(CoreError::InvalidInput(
                        "The Windows login doesn't unlock this vault; use the vault password.".into(),
                    ));
                };
                let protector = Arc::clone(&inner.protector);
                let entropy = dpapi_entropy(&inner.ctx);
                let bytes = blocking(move || protector.unprotect(&blob, &entropy))
                    .await
                    .map_err(|err| {
                        CoreError::Vault(format!(
                            "Windows could not unlock the vault ({err}). This happens after an administrator resets the Windows password or on another account; use the vault password"
                        ))
                    })?;
                Key::from_bytes(&bytes)?
            }
            UnlockMethod::MasterPassword(password) => inner
                .unwrap_with_password(&meta, &password)
                .await?
                .ok_or(CoreError::WrongVaultPassword)?,
        };
        inner.open_with(key, windows_login);
        Ok(())
    }

    fn lock(&self) {
        let inner = &self.inner;
        let mut state = locks::lock(&inner.state);
        state.open = None;
        inner.publish(&state);
    }

    async fn verify_password(&self, password: &SecretString) -> Result<bool> {
        let inner = &self.inner;
        let meta = inner.meta().await?;
        Ok(inner.unwrap_with_password(&meta, password).await?.is_some())
    }

    async fn change_password(&self, current: &SecretString, new: SecretString) -> Result<()> {
        let inner = &self.inner;
        check_master_password(&new)?;
        let meta = inner.meta().await?;
        let key = inner
            .unwrap_with_password(&meta, current)
            .await?
            .ok_or(CoreError::WrongVaultPassword)?;
        let (salt, wrapped) = inner.wrap_with_password(&key, new).await?;
        inner
            .store
            .set_vault_password(&inner.ctx, &salt, &inner.options.kdf, &wrapped)
            .await
    }

    async fn set_windows_login(&self, password: &SecretString, enabled: bool) -> Result<()> {
        let inner = &self.inner;
        let meta = inner.meta().await?;
        let key = inner
            .unwrap_with_password(&meta, password)
            .await?
            .ok_or(CoreError::WrongVaultPassword)?;
        let blob = if enabled {
            Some(inner.protect_with_dpapi(&key).await?)
        } else {
            None
        };
        inner.store.set_vault_dpapi_key(&inner.ctx, blob.as_deref()).await?;
        let mut state = locks::lock(&inner.state);
        state.windows_login = Some(enabled);
        Ok(())
    }

    async fn list(&self, ctx: &Context) -> Result<Vec<SecretMeta>> {
        self.inner.check_ctx(ctx)?;
        self.inner.store.vault_items(ctx).await
    }

    async fn put(&self, ctx: &Context, kind: SecretKind, label: &str, secret: SecretString) -> Result<SecretId> {
        let inner = &self.inner;
        inner.check_ctx(ctx)?;
        inner.with_key(|_| Ok(()))?;
        let label = clean_label(label)?;
        check_secret(kind, &secret)?;
        if inner.store.vault_label_taken(ctx, &label, None).await? {
            return Err(CoreError::InvalidInput(format!(
                "There is already a secret labelled '{label}'."
            )));
        }
        let id = SecretId(Uuid::new_v4());
        let aad = item_aad(ctx, id, kind);
        let (nonce, ciphertext) = inner.with_key(|key| crypto::seal(key, secret.expose().as_bytes(), &aad))?;
        inner
            .store
            .insert_vault_item(ctx, id.0, kind, &label, &nonce, &ciphertext)
            .await?;
        Ok(id)
    }

    async fn replace(&self, ctx: &Context, id: SecretId, secret: SecretString) -> Result<()> {
        let inner = &self.inner;
        inner.check_ctx(ctx)?;
        inner.with_key(|_| Ok(()))?;
        let kind = inner
            .store
            .vault_item_kind(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("secret {id}")))?;
        check_secret(kind, &secret)?;
        let aad = item_aad(ctx, id, kind);
        let (nonce, ciphertext) = inner.with_key(|key| crypto::seal(key, secret.expose().as_bytes(), &aad))?;
        if !inner
            .store
            .update_vault_item_cipher(ctx, id, &nonce, &ciphertext)
            .await?
        {
            return Err(CoreError::UnknownTarget(format!("secret {id}")));
        }
        Ok(())
    }

    async fn rename(&self, ctx: &Context, id: SecretId, label: &str) -> Result<()> {
        let inner = &self.inner;
        inner.check_ctx(ctx)?;
        inner.with_key(|_| Ok(()))?;
        let label = clean_label(label)?;
        if inner.store.vault_label_taken(ctx, &label, Some(id)).await? {
            return Err(CoreError::InvalidInput(format!(
                "There is already a secret labelled '{label}'."
            )));
        }
        if !inner.store.rename_vault_item(ctx, id, &label).await? {
            return Err(CoreError::UnknownTarget(format!("secret {id}")));
        }
        Ok(())
    }

    async fn delete(&self, ctx: &Context, id: SecretId) -> Result<()> {
        let inner = &self.inner;
        inner.check_ctx(ctx)?;
        inner.with_key(|_| Ok(()))?;
        if !inner.store.delete_vault_item(ctx, id).await? {
            return Err(CoreError::UnknownTarget(format!("secret {id}")));
        }
        Ok(())
    }

    async fn get(&self, ctx: &Context, id: SecretId) -> Result<SecretString> {
        let inner = &self.inner;
        inner.check_ctx(ctx)?;
        inner.with_key(|_| Ok(()))?;
        let item = inner
            .store
            .vault_item_cipher(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("secret {id}")))?;
        let aad = item_aad(ctx, id, item.kind);
        let plaintext = inner
            .with_key(|key| crypto::open(key, &item.nonce, &item.ciphertext, &aad))?
            .ok_or_else(|| {
                CoreError::Vault(format!(
                    "the {} '{}' could not be decrypted: the vault data was changed or damaged",
                    item.kind.label(),
                    item.label
                ))
            })?;
        SecretString::from_utf8(plaintext)
    }
}
