/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use crate::{
	constants::{get_default_user_agent, APPLICATION_NAME, IS_INTERACTIVE_CLI, PRODUCT_NAME_LONG},
	info, log,
	state::{LauncherPaths, PersistedState},
	trace,
	util::{
		errors::{
			wrap, AnyError, AuthenticationRequired, OAuthError, RefreshTokenNotAvailableError,
			StatusError, WrappedError,
		},
		input::prompt_options,
	},
	warning,
};
use jiff::{SignedDuration, Timestamp};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
	fmt::Display,
	future::Future,
	path::PathBuf,
	pin::Pin,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
	time::Duration,
};
use tokio::time::sleep;
use tunnels::{
	contracts::PROD_FIRST_PARTY_APP_ID,
	management::{Authorization, AuthorizationProvider, HttpError},
};

#[derive(Deserialize)]
struct DeviceCodeResponse {
	device_code: String,
	user_code: String,
	message: Option<String>,
	verification_uri: String,
	expires_in: i64,
}

#[derive(Deserialize, Debug)]
struct AuthenticationResponse {
	access_token: String,
	refresh_token: Option<String>,
	expires_in: Option<i64>,
}

#[derive(Deserialize)]
struct AuthenticationError {
	error: String,
	#[serde(default)]
	error_codes: Vec<u32>,
	suberror: Option<String>,
}

#[derive(clap::ValueEnum, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProvider {
	Microsoft,
	Github,
}

impl Display for AuthProvider {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AuthProvider::Microsoft => write!(f, "Microsoft Account"),
			AuthProvider::Github => write!(f, "GitHub Account"),
		}
	}
}

impl AuthProvider {
	pub fn client_id(&self) -> &'static str {
		match self {
			AuthProvider::Microsoft => "aebc6443-996d-45c2-90f0-388ff96faa56",
			AuthProvider::Github => "01ab8ac9400c4e429b23",
		}
	}

	pub fn code_uri(&self) -> &'static str {
		match self {
			AuthProvider::Microsoft => {
				"https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"
			}
			AuthProvider::Github => "https://github.com/login/device/code",
		}
	}

	pub fn grant_uri(&self) -> &'static str {
		match self {
			AuthProvider::Microsoft => {
				"https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
			}
			AuthProvider::Github => "https://github.com/login/oauth/access_token",
		}
	}

	pub fn get_default_scopes(&self) -> String {
		match self {
			AuthProvider::Microsoft => {
				format!("{PROD_FIRST_PARTY_APP_ID}/.default+offline_access+profile+openid")
			}
			AuthProvider::Github => "read:user+read:org".to_string(),
		}
	}
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StoredCredential {
	#[serde(rename = "p")]
	pub(crate) provider: AuthProvider,
	#[serde(rename = "a")]
	access_token: String,
	#[serde(rename = "r")]
	refresh_token: Option<String>,
	#[serde(rename = "e")]
	expires_at: Option<Timestamp>,
}

const GH_USER_ENDPOINT: &str = "https://api.github.com/user";

async fn get_github_user(
	client: &reqwest::Client,
	access_token: &str,
) -> Result<reqwest::Response, reqwest::Error> {
	client
		.get(GH_USER_ENDPOINT)
		.header("Authorization", format!("token {access_token}"))
		.header("User-Agent", get_default_user_agent())
		.send()
		.await
}

impl StoredCredential {
	/// Returns the raw access token string.
	pub fn access_token(&self) -> &str {
		&self.access_token
	}

	/// Returns the remaining lifetime in whole seconds, omitting unknown or non-positive lifetimes.
	pub fn expires_in(&self, now: Timestamp) -> Option<i64> {
		self.expires_at
			.map(|expiry| expiry.duration_since(now).as_secs())
			.filter(|seconds| *seconds > 0)
	}

	pub async fn is_expired(&self, log: &log::Logger, client: &reqwest::Client) -> bool {
		match self.provider {
			AuthProvider::Microsoft => self
				.expires_at
				.map(|e| Timestamp::now() + SignedDuration::from_secs(5 * 60) > e)
				.unwrap_or(false),

			// Make an auth request to Github. Mark the credential as expired
			// only on a verifiable 4xx code. We don't error on any failed
			// request since then a drop in connection could "require" a refresh
			AuthProvider::Github => {
				let res = get_github_user(client, &self.access_token).await;
				let res = match res {
					Ok(r) => r,
					Err(e) => {
						warning!(log, "failed to check GitHub token: {}", e);
						return false;
					}
				};

				if res.status().is_success() {
					return false;
				}

				// Permission, SSO, throttling and server failures do not prove
				// that a credential has been revoked.
				res.status() == reqwest::StatusCode::UNAUTHORIZED
			}
		}
	}

	fn from_response(auth: AuthenticationResponse, provider: AuthProvider) -> Self {
		StoredCredential {
			provider,
			access_token: auth.access_token,
			refresh_token: auth.refresh_token,
			expires_at: auth
				.expires_in
				.map(|e| Timestamp::now() + SignedDuration::from_secs(e)),
		}
	}
}

struct CredentialStorage {
	storage: Box<dyn StorageImplementation>,
	fallback_storage: Option<FileStorage>,
}

impl CredentialStorage {
	fn file_storage(&mut self, prefer_file: bool) -> std::io::Result<Option<&mut FileStorage>> {
		match self.fallback_storage.as_mut() {
			Some(file) if prefer_file || file.0.try_exists()? => Ok(Some(file)),
			_ => Ok(None),
		}
	}

	fn read(&mut self, prefer_file: bool) -> Result<Option<StoredCredential>, WrappedError> {
		match self
			.file_storage(prefer_file)
			.map_err(|e| wrap(e, "could not locate credential file"))?
		{
			Some(file) => file.read(),
			None => self.storage.read(),
		}
		.map_err(|e| wrap(e, "could not read stored credentials"))
	}

	fn store(
		&mut self,
		prefer_file: bool,
		value: StoredCredential,
		log: &log::Logger,
	) -> Result<(), AnyError> {
		if let Some(file) = self
			.file_storage(prefer_file)
			.map_err(|e| wrap(e, "could not locate credential file"))?
		{
			file.store(value.clone())?;
		} else if let Err(error) = self.storage.store(value.clone()) {
			match self.fallback_storage.as_mut() {
				Some(file) => {
					warning!(
						log,
						"Failed to update keyring; using file keychain: {}",
						error
					);
					file.store(value.clone())?;
				}
				None => return Err(error),
			}
		}
		Ok(())
	}
}

#[derive(Clone)]
pub struct Auth {
	client: reqwest::Client,
	log: log::Logger,
	file_storage_path: PathBuf,
	prefer_file_storage: bool,
	storage: Arc<std::sync::Mutex<Option<CredentialStorage>>>,
	/// Prefix for keyring entries, derived from the namespace.
	keyring_prefix: String,
	/// When set, restricts authentication to only this provider.
	/// The user will not be prompted to choose a provider.
	forced_provider: Option<AuthProvider>,
	/// Disallows implicit login while retaining explicit login APIs.
	non_interactive: bool,
	authentication_required: Arc<AtomicBool>,
	refresh_lock: Arc<tokio::sync::Mutex<()>>,
	storage_io_lock: Arc<tokio::sync::Mutex<()>>,
	#[cfg(test)]
	test_endpoints: Option<(String, String)>,
	#[cfg(test)]
	test_request_timeout: Option<Duration>,
	#[cfg(test)]
	test_keepalive_sleeping: Option<Arc<tokio::sync::Notify>>,
}

trait StorageImplementation: Send + Sync {
	fn read(&mut self) -> Result<Option<StoredCredential>, AnyError>;
	fn store(&mut self, value: StoredCredential) -> Result<(), AnyError>;
	fn clear(&mut self) -> Result<(), AnyError>;
}

// unseal decrypts and deserializes the value
fn seal<T>(value: &T) -> String
where
	T: Serialize + ?Sized,
{
	let dec = serde_json::to_string(value).expect("expected to serialize");
	if std::env::var("VSCODE_CLI_DISABLE_KEYCHAIN_ENCRYPT").is_ok() {
		return dec;
	}
	encrypt(&dec)
}

// unseal decrypts and deserializes the value
fn unseal<T>(value: &str) -> Option<T>
where
	T: DeserializeOwned,
{
	// small back-compat for old unencrypted values, or if VSCODE_CLI_DISABLE_KEYCHAIN_ENCRYPT set
	if let Ok(v) = serde_json::from_str::<T>(value) {
		return Some(v);
	}

	let dec = decrypt(value)?;
	serde_json::from_str::<T>(&dec).ok()
}

#[cfg(target_os = "windows")]
const KEYCHAIN_ENTRY_LIMIT: usize = 1024;
#[cfg(not(target_os = "windows"))]
const KEYCHAIN_ENTRY_LIMIT: usize = 128 * 1024;

const CONTINUE_MARKER: &str = "<MORE>";

/// Implementation that wraps the KeyringStorage on Linux to avoid
/// https://github.com/hwchen/keyring-rs/issues/132
#[cfg(target_os = "linux")]
struct ThreadKeyringStorage {
	s: Option<KeyringStorage>,
}

#[cfg(target_os = "linux")]
impl ThreadKeyringStorage {
	fn new(prefix: String) -> Self {
		Self {
			s: Some(KeyringStorage::new(prefix)),
		}
	}

	fn thread_op<R, Fn>(&mut self, f: Fn) -> Result<R, AnyError>
	where
		Fn: 'static + Send + FnOnce(&mut KeyringStorage) -> Result<R, AnyError>,
		R: 'static + Send,
	{
		use crate::util::errors::CodeError;
		use std::thread;

		let mut s = match self.s.take() {
			Some(s) => s,
			None => return Err(CodeError::KeyringTimeout.into()),
		};

		// It seems like on Linux communication to the keyring can block indefinitely.
		// Fall back after a 5 second timeout.
		let (sender, receiver) = std::sync::mpsc::channel();
		let tsender = sender.clone();

		thread::spawn(move || sender.send(Some((f(&mut s), s))));
		thread::spawn(move || {
			thread::sleep(std::time::Duration::from_secs(5));
			let _ = tsender.send(None);
		});

		match receiver.recv().unwrap() {
			Some((r, s)) => {
				self.s = Some(s);
				r
			}
			None => Err(CodeError::KeyringTimeout.into()),
		}
	}
}

#[cfg(target_os = "linux")]
impl StorageImplementation for ThreadKeyringStorage {
	fn read(&mut self) -> Result<Option<StoredCredential>, AnyError> {
		self.thread_op(|s| s.read())
	}

	fn store(&mut self, value: StoredCredential) -> Result<(), AnyError> {
		self.thread_op(move |s| s.store(value))
	}

	fn clear(&mut self) -> Result<(), AnyError> {
		self.thread_op(|s| s.clear())
	}
}

struct KeyringStorage {
	prefix: String,
	entries: Vec<keyring::Entry>,
}

impl KeyringStorage {
	fn new(prefix: String) -> Self {
		Self {
			prefix,
			entries: vec![],
		}
	}
}

macro_rules! get_next_entry {
	($self: expr, $i: expr) => {
		match $self.entries.get($i) {
			Some(e) => e,
			None => {
				let e = keyring::Entry::new(&$self.prefix, &format!("{}-{}", $self.prefix, $i))
					.unwrap();
				$self.entries.push(e);
				$self.entries.last().unwrap()
			}
		}
	};
}

impl StorageImplementation for KeyringStorage {
	fn read(&mut self) -> Result<Option<StoredCredential>, AnyError> {
		let mut str = String::new();

		for i in 0.. {
			let entry = get_next_entry!(self, i);
			let next_chunk = match entry.get_password() {
				Ok(value) => value,
				Err(keyring::Error::NoEntry) => return Ok(None), // missing entries?
				Err(e) => return Err(wrap(e, "error reading keyring").into()),
			};

			if next_chunk.ends_with(CONTINUE_MARKER) {
				str.push_str(&next_chunk[..next_chunk.len() - CONTINUE_MARKER.len()]);
			} else {
				str.push_str(&next_chunk);
				break;
			}
		}

		unseal(&str)
			.map(Some)
			.ok_or_else(|| wrap("", "stored keyring credential could not be decoded").into())
	}

	fn store(&mut self, value: StoredCredential) -> Result<(), AnyError> {
		let sealed = seal(&value);
		let step_size = KEYCHAIN_ENTRY_LIMIT - CONTINUE_MARKER.len();

		for i in (0..sealed.len()).step_by(step_size) {
			let entry = get_next_entry!(self, i / step_size);

			let cutoff = i + step_size;
			let stored = if cutoff <= sealed.len() {
				let mut part = sealed[i..cutoff].to_string();
				part.push_str(CONTINUE_MARKER);
				entry.set_password(&part)
			} else {
				entry.set_password(&sealed[i..])
			};

			if let Err(e) = stored {
				return Err(wrap(e, "error updating keyring").into());
			}
		}

		Ok(())
	}

	fn clear(&mut self) -> Result<(), AnyError> {
		self.read().ok(); // make sure component parts are available
		for entry in self.entries.iter() {
			entry
				.delete_password()
				.map_err(|e| wrap(e, "error updating keyring"))?;
		}
		self.entries.clear();

		Ok(())
	}
}

struct FileStorage(PathBuf);

impl StorageImplementation for FileStorage {
	fn read(&mut self) -> Result<Option<StoredCredential>, AnyError> {
		let contents = match std::fs::read_to_string(&self.0) {
			Ok(contents) => contents,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
			Err(e) => return Err(wrap(e, "could not read credential file").into()),
		};
		let sealed: Option<String> = serde_json::from_str(&contents)
			.map_err(|_| wrap("", "credential file could not be decoded"))?;
		match sealed {
			None => Ok(None),
			Some(value) => unseal(&value)
				.map(Some)
				.ok_or_else(|| wrap("", "stored file credential could not be decoded").into()),
		}
	}

	fn store(&mut self, value: StoredCredential) -> Result<(), AnyError> {
		PersistedState::new_with_mode(self.0.clone(), 0o600)
			.save(Some(seal(&value)))
			.map_err(|e| e.into())
	}

	fn clear(&mut self) -> Result<(), AnyError> {
		PersistedState::<Option<String>>::new_with_mode(self.0.clone(), 0o600)
			.save(None)
			.map_err(|e| e.into())
	}
}

impl Auth {
	pub fn new(paths: &LauncherPaths, log: log::Logger) -> Auth {
		Self::with_namespace(paths, log, None)
	}

	/// Creates an `Auth` instance with an isolated credential namespace.
	/// Credentials are stored separately from the global CLI credentials,
	/// so logging in here does not affect tunnel or other global auth.
	pub fn with_namespace(
		paths: &LauncherPaths,
		log: log::Logger,
		namespace: Option<String>,
	) -> Auth {
		let filename = match &namespace {
			None => "token.json".to_string(),
			Some(ns) => format!("token-{ns}.json"),
		};
		let keyring_prefix = match &namespace {
			None => "vscode-cli".to_string(),
			Some(ns) => format!("vscode-cli-{ns}"),
		};
		Auth {
			log,
			client: reqwest::Client::new(),
			file_storage_path: paths.root().join(filename),
			prefer_file_storage: std::env::var_os("VSCODE_CLI_USE_FILE_KEYCHAIN").is_some(),
			storage: Arc::new(std::sync::Mutex::new(None)),
			keyring_prefix,
			forced_provider: None,
			non_interactive: false,
			authentication_required: Arc::new(AtomicBool::new(false)),
			refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
			storage_io_lock: Arc::new(tokio::sync::Mutex::new(())),
			#[cfg(test)]
			test_endpoints: None,
			#[cfg(test)]
			test_request_timeout: None,
			#[cfg(test)]
			test_keepalive_sleeping: None,
		}
	}

	/// Restricts this `Auth` instance to only allow the given provider.
	/// When set, the user will not be prompted to choose a provider.
	pub fn set_provider(&mut self, provider: AuthProvider) {
		self.forced_provider = Some(provider);
	}

	/// Restricts implicit credential acquisition to stored credentials and
	/// provider-supported silent refresh. Explicit login remains available.
	pub fn set_non_interactive(&mut self) {
		self.non_interactive = true;
	}

	/// Whether the latest credential check requires an explicit login. This
	/// remains available when the SDK erases the original authentication error.
	pub fn authentication_required(&self) -> bool {
		self.authentication_required.load(Ordering::Relaxed)
	}

	fn record_authentication_result<T>(&self, result: &Result<T, AnyError>) {
		self.authentication_required.store(
			matches!(result, Err(AnyError::AuthenticationRequired(_))),
			Ordering::Relaxed,
		);
	}

	fn auth_request(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
		if self.non_interactive {
			let timeout = Duration::from_secs(30);
			#[cfg(test)]
			let timeout = self.test_request_timeout.unwrap_or(timeout);
			request.timeout(timeout)
		} else {
			request
		}
	}

	fn prefers_file_storage(&self) -> bool {
		self.prefer_file_storage
	}

	async fn with_storage_io<T: Send + 'static>(
		&self,
		op: impl FnOnce(Self) -> Result<T, AnyError> + Send + 'static,
	) -> Result<T, AnyError> {
		let permit = self.storage_io_lock.clone().lock_owned().await;
		let auth = self.clone();
		// Native keyring I/O is not cancellable. The blocking task retains the
		// permit even if its caller is cancelled, preventing repeated stalled
		// reads from accumulating blocking tasks during reconnect retries.
		tokio::task::spawn_blocking(move || {
			let _permit = permit;
			op(auth)
		})
		.await
		.map_err(|_| wrap("", "credential storage task failed"))?
	}

	async fn read_current_credential(&self) -> Result<Option<StoredCredential>, AnyError> {
		self.with_storage_io(|auth| auth.get_current_credential().map_err(Into::into))
			.await
	}

	async fn save_credentials(&self, credential: StoredCredential) -> Result<(), AnyError> {
		self.with_storage_io(move |auth| auth.store_credentials(credential))
			.await
	}

	fn with_storage<T, F>(&self, op: F) -> T
	where
		F: FnOnce(&mut CredentialStorage) -> T,
	{
		let mut opt = self.storage.lock().unwrap();
		if let Some(s) = opt.as_mut() {
			return op(s);
		}

		#[cfg(not(target_os = "linux"))]
		let keyring_storage = KeyringStorage::new(self.keyring_prefix.clone());
		#[cfg(target_os = "linux")]
		let keyring_storage = ThreadKeyringStorage::new(self.keyring_prefix.clone());
		let mut storage = CredentialStorage {
			storage: Box::new(keyring_storage),
			fallback_storage: Some(FileStorage(self.file_storage_path.clone())),
		};

		let out = op(&mut storage);
		*opt = Some(storage);
		out
	}

	/// Gets a tunnel Authentication for use in the tunnel management API.
	pub async fn get_tunnel_authentication(&self) -> Result<Authorization, AnyError> {
		let cred = self.get_credential().await?;
		let auth = match cred.provider {
			AuthProvider::Microsoft => Authorization::Bearer(cred.access_token),
			AuthProvider::Github => Authorization::Github(format!(
				"client_id={} {}",
				cred.provider.client_id(),
				cred.access_token
			)),
		};

		Ok(auth)
	}

	/// Authoritatively reads the current backing store, including file fallback
	/// selected by a separate CLI login. Storage failures are not missing logins.
	pub fn get_current_credential(&self) -> Result<Option<StoredCredential>, WrappedError> {
		self.with_storage(|storage| storage.read(self.prefers_file_storage()))
	}

	/// Clears login info from the keyring.
	pub fn clear_credentials(&self) -> Result<(), AnyError> {
		self.with_storage(|storage| {
			match storage
				.file_storage(self.prefers_file_storage())
				.map_err(|e| wrap(e, "could not locate credential file"))?
			{
				Some(file) => file.clear()?,
				None => storage.storage.clear()?,
			}
			Ok(())
		})
	}

	/// Runs the login flow, optionally pre-filling a provider and/or access token.
	pub async fn login(
		&self,
		provider: Option<AuthProvider>,
		access_token: Option<String>,
		refresh_token: Option<String>,
	) -> Result<StoredCredential, AnyError> {
		let provider = match provider {
			Some(p) => p,
			None => self.prompt_for_provider().await?,
		};

		let credentials = match access_token {
			Some(t) => StoredCredential {
				provider,
				access_token: t,
				// if a refresh token is given, assume it's valid now but refresh it
				// soon in order to get the real expiry time.
				expires_at: refresh_token
					.as_ref()
					.map(|_| Timestamp::now() + SignedDuration::from_secs(5 * 60)),
				refresh_token,
			},
			None => self.do_device_code_flow_with_provider(provider).await?,
		};

		self.save_credentials(credentials.clone()).await?;
		Ok(credentials)
	}

	/// Runs the device-flow login for a specific provider with custom OAuth
	/// scopes. Unlike [`login`], this is purpose-built for agent host auth
	/// where the scopes are dictated by the server's protected resource
	/// metadata rather than hardcoded defaults.
	pub async fn login_with_scopes(
		&self,
		provider: AuthProvider,
		scopes: Option<String>,
	) -> Result<StoredCredential, AnyError> {
		let credentials = self
			.do_device_code_flow_with_scopes(provider, scopes)
			.await?;
		self.save_credentials(credentials.clone()).await?;
		Ok(credentials)
	}

	/// Gets current credentials, refreshing silently when supported. Implicit
	/// device login is disabled by [`Self::set_non_interactive`].
	pub async fn get_credential(&self) -> Result<StoredCredential, AnyError> {
		if self.non_interactive {
			return self.get_credential_silently(false).await;
		}
		let entry = match self.read_current_credential().await {
			Ok(Some(old_creds)) => {
				trace!(self.log, "Found token in keyring");
				match self.maybe_refresh_token(&old_creds).await {
					Ok(Some(new_creds)) => {
						match self
							.store_refreshed_credentials(&old_creds, new_creds)
							.await?
						{
							Some(creds) => creds,
							None => self
								.read_current_credential()
								.await?
								.ok_or(AuthenticationRequired())?,
						}
					}
					Ok(None) => old_creds,
					Err(
						e @ (AnyError::AuthenticationRequired(_)
						| AnyError::RefreshTokenNotAvailableError(_)),
					) => {
						info!(self.log, "error refreshing token: {}", e);
						crate::tunnels::machine_status::emit_token_error(e.to_string());
						let new_creds = self
							.do_device_code_flow_with_provider(old_creds.provider)
							.await?;
						self.save_credentials(new_creds.clone()).await?;
						new_creds
					}
					Err(error) => return Err(error),
				}
			}

			Ok(None) => {
				trace!(self.log, "No token in keyring, getting a new one");
				let creds = self.do_device_code_flow().await?;
				self.save_credentials(creds.clone()).await?;
				creds
			}

			Err(e) => {
				warning!(
					self.log,
					"Error reading token from keyring, getting a new one: {}",
					e
				);
				let creds = self.do_device_code_flow().await?;
				self.save_credentials(creds.clone()).await?;
				creds
			}
		};

		self.authentication_required.store(false, Ordering::Relaxed);
		Ok(entry)
	}

	async fn get_credential_silently(
		&self,
		force_refresh: bool,
	) -> Result<StoredCredential, AnyError> {
		let _guard = self.refresh_lock.lock().await;
		self.authentication_required.store(false, Ordering::Relaxed);
		let result = self.get_stored_credential(force_refresh).await;
		self.record_authentication_result(&result);
		result
	}

	async fn get_stored_credential(
		&self,
		force_refresh: bool,
	) -> Result<StoredCredential, AnyError> {
		// A login may replace the credential while a provider request is in
		// flight. Retry against that replacement, without an unbounded busy loop.
		for _ in 0..3 {
			let credential = self
				.read_current_credential()
				.await?
				.ok_or(AuthenticationRequired())?;
			if self
				.forced_provider
				.is_some_and(|provider| credential.provider != provider)
			{
				return Err(AuthenticationRequired().into());
			}

			let refreshed = if force_refresh {
				self.do_refresh_token(&credential).await
			} else {
				self.maybe_refresh_token(&credential).await
			};
			let current = self.read_current_credential().await?;
			if current.as_ref() != Some(&credential) {
				continue;
			}
			return match refreshed? {
				Some(refreshed) => {
					match self
						.store_refreshed_credentials(&credential, refreshed)
						.await?
					{
						Some(credential) => Ok(credential),
						None => continue,
					}
				}
				None => Ok(credential),
			};
		}
		Err(wrap(
			"",
			"stored credentials changed during authentication; retrying",
		)
		.into())
	}

	/// Best-effort compare-before-write, serialized with other writes through
	/// this Auth. Backends have no cross-process compare-and-swap: an external
	/// writer can still race between this reread and the actual write.
	async fn store_refreshed_credentials(
		&self,
		previous: &StoredCredential,
		refreshed: StoredCredential,
	) -> Result<Option<StoredCredential>, AnyError> {
		let previous = previous.clone();
		self.with_storage_io(move |auth| {
			auth.with_storage(|storage| {
				if storage.read(auth.prefers_file_storage())?.as_ref() != Some(&previous) {
					return Ok(None);
				}
				storage.store(auth.prefers_file_storage(), refreshed.clone(), &auth.log)?;
				Ok(Some(refreshed))
			})
		})
		.await
	}

	/// Stores credentials, logging a warning if it fails.
	fn store_credentials(&self, creds: StoredCredential) -> Result<(), AnyError> {
		let result = self.with_storage(|storage| {
			let result = storage.store(self.prefers_file_storage(), creds, &self.log);
			if let Err(e) = &result {
				warning!(
					self.log,
					"Failed to update keyring with new credentials: {}",
					e
				);
			}
			result
		});
		if result.is_ok() {
			self.authentication_required.store(false, Ordering::Relaxed);
		}
		result
	}

	/// Refreshes the token in the credentials if necessary. Returns None if
	/// the token is up to date, or Some new token otherwise.
	async fn maybe_refresh_token(
		&self,
		creds: &StoredCredential,
	) -> Result<Option<StoredCredential>, AnyError> {
		match creds.provider {
			AuthProvider::Github => match self.touch_github_token(creds).await {
				Ok(()) => return Ok(None),
				Err(AnyError::AuthenticationRequired(_)) if creds.refresh_token.is_some() => {}
				Err(error) => return Err(error),
			},
			AuthProvider::Microsoft if !creds.is_expired(&self.log, &self.client).await => {
				return Ok(None);
			}
			_ => {}
		}
		self.do_refresh_token(creds).await
	}

	/// Refreshes the token in the credentials. Returns an error if the process failed.
	/// Returns None if the token didn't change.
	async fn do_refresh_token(
		&self,
		creds: &StoredCredential,
	) -> Result<Option<StoredCredential>, AnyError> {
		match &creds.refresh_token {
			Some(t) => {
				let body = url::form_urlencoded::Serializer::new(String::new())
					.append_pair("client_id", creds.provider.client_id())
					.append_pair("grant_type", "refresh_token")
					.append_pair("refresh_token", t)
					.finish();
				self.do_grant(creds.provider, body)
					.await
					.map(|mut refreshed| {
						if refreshed.refresh_token.is_none() {
							refreshed.refresh_token.clone_from(&creds.refresh_token);
						}
						Some(refreshed)
					})
			}
			None => match creds.provider {
				// Checking a GitHub token is not silent reissuance. A rejected
				// token without a refresh grant requires an explicit login.
				AuthProvider::Github => self.touch_github_token(creds).await.map(|_| None),
				AuthProvider::Microsoft if !creds.is_expired(&self.log, &self.client).await => {
					Ok(None)
				}
				_ if self.non_interactive => Err(AuthenticationRequired().into()),
				_ => Err(RefreshTokenNotAvailableError().into()),
			},
		}
	}

	/// Does a "grant token" request.
	async fn do_grant(
		&self,
		provider: AuthProvider,
		body: String,
	) -> Result<StoredCredential, AnyError> {
		let grant_uri = self.grant_uri(provider);
		let response = self
			.auth_request(
				self.client
					.post(grant_uri)
					.body(body)
					.header("Accept", "application/json")
					.header("Content-Type", "application/x-www-form-urlencoded"),
			)
			.send()
			.await?;

		let status_code = response.status().as_u16();
		let body = response.bytes().await?;
		if (200..300).contains(&status_code) {
			if let Ok(body) = serde_json::from_slice::<AuthenticationResponse>(&body) {
				return Ok(StoredCredential::from_response(body, provider));
			}
		}

		Err(Auth::handle_grant_error(grant_uri, status_code, body))
	}

	/// GH doesn't have a refresh token, but does limit to the 10 most recently
	/// used tokens per user (#9052), so for the github "refresh" just request
	/// the current user.
	async fn touch_github_token(&self, credential: &StoredCredential) -> Result<(), AnyError> {
		let response = self
			.auth_request(
				self.client
					.get(self.github_user_uri())
					.header(
						"Authorization",
						format!("token {}", credential.access_token),
					)
					.header("User-Agent", get_default_user_agent()),
			)
			.send()
			.await?;
		if response.status().is_success() {
			return Ok(());
		}

		let status_code = response.status().as_u16();
		if status_code == 401 {
			return Err(AuthenticationRequired().into());
		}
		// A 403 can mean permissions, rate limits or an SSO requirement, not
		// invalid credentials. Do not retain or log provider response bodies.
		Err(StatusError {
			url: GH_USER_ENDPOINT.to_string(),
			status_code,
			body: "GitHub credential validation failed".to_string(),
		}
		.into())
	}

	fn handle_grant_error(url: &str, status_code: u16, body: bytes::Bytes) -> AnyError {
		if !(status_code == 429 || status_code >= 500) {
			if let Ok(res) = serde_json::from_slice::<AuthenticationError>(&body) {
				// Entra can report SSO/MFA or policy requirements as invalid_grant.
				// Preserve those as OAuth failures rather than token revocation.
				let interaction_required = res.suberror.as_deref().is_some_and(|suberror| {
					matches!(
						suberror,
						"basic_action" | "additional_action" | "consent_required" | "message_only"
					)
				}) || res
					.error_codes
					.iter()
					.any(|code| matches!(*code, 50076 | 50079 | 50158 | 53000 | 53001 | 53003));
				if interaction_required {
					return OAuthError {
						error: "interaction_required".to_string(),
						error_description: None,
					}
					.into();
				}
				let error = match res.error.as_str() {
					"invalid_grant" | "invalid_token" | "bad_refresh_token" | "expired_token"
						if status_code == 400
							|| status_code == 401
							|| (200..300).contains(&status_code) =>
					{
						return AuthenticationRequired().into();
					}
					"authorization_pending" => "authorization_pending",
					"slow_down" => "slow_down",
					"interaction_required" => "interaction_required",
					"consent_required" => "consent_required",
					"access_denied" => "access_denied",
					"insufficient_scope" => "insufficient_scope",
					"invalid_client" => "invalid_client",
					_ => "oauth_error",
				};
				return OAuthError {
					error: error.to_string(),
					error_description: None,
				}
				.into();
			}
			if status_code == 401 {
				return AuthenticationRequired().into();
			}
		}

		StatusError {
			body: "authentication endpoint rejected the request".to_string(),
			status_code,
			url: url.to_string(),
		}
		.into()
	}

	fn github_user_uri(&self) -> &str {
		#[cfg(test)]
		if let Some((github, _)) = &self.test_endpoints {
			return github;
		}
		GH_USER_ENDPOINT
	}

	fn grant_uri(&self, provider: AuthProvider) -> &str {
		#[cfg(test)]
		if let Some((_, grant)) = &self.test_endpoints {
			return grant;
		}
		provider.grant_uri()
	}
	/// Implements the device code flow, returning the credentials upon success.
	async fn do_device_code_flow(&self) -> Result<StoredCredential, AnyError> {
		let provider = self.prompt_for_provider().await?;
		self.do_device_code_flow_with_scopes(provider, None).await
	}

	async fn prompt_for_provider(&self) -> Result<AuthProvider, AnyError> {
		if let Some(provider) = self.forced_provider {
			return Ok(provider);
		}

		if !*IS_INTERACTIVE_CLI {
			info!(
				self.log,
				"Using GitHub for authentication, run `{} tunnel user login --provider <provider>` option to change this.",
				APPLICATION_NAME
			);
			return Ok(AuthProvider::Github);
		}

		let provider = prompt_options(
			format!("How would you like to log in to {PRODUCT_NAME_LONG}?"),
			&[AuthProvider::Microsoft, AuthProvider::Github],
		)?;

		Ok(provider)
	}

	async fn do_device_code_flow_with_provider(
		&self,
		provider: AuthProvider,
	) -> Result<StoredCredential, AnyError> {
		self.do_device_code_flow_with_scopes(provider, None).await
	}

	/// Runs the OAuth device code flow with optional custom scopes.
	/// If `scopes` is `None`, falls back to the provider's default scopes.
	pub async fn do_device_code_flow_with_scopes(
		&self,
		provider: AuthProvider,
		scopes: Option<String>,
	) -> Result<StoredCredential, AnyError> {
		let scopes = scopes.unwrap_or_else(|| provider.get_default_scopes());
		loop {
			#[cfg(test)]
			let code_uri = self
				.test_endpoints
				.as_ref()
				.map_or(provider.code_uri(), |(_, grant)| grant.as_str());
			#[cfg(not(test))]
			let code_uri = provider.code_uri();
			let init_code = self
				.client
				.post(code_uri)
				.header("Accept", "application/json")
				.body(format!(
					"client_id={}&scope={}",
					provider.client_id(),
					scopes,
				))
				.send()
				.await?;

			if !init_code.status().is_success() {
				return Err(StatusError {
					url: provider.code_uri().to_string(),
					status_code: init_code.status().as_u16(),
					body: "device authorization request failed".to_string(),
				}
				.into());
			}

			let init_code_json = init_code.json::<DeviceCodeResponse>().await?;
			let expires_at =
				Timestamp::now() + SignedDuration::from_secs(init_code_json.expires_in);

			match &init_code_json.message {
				Some(m) => self.log.result(m),
				None => self.log.result(format!(
					"To grant access to the server, please log into {} and use code {}",
					init_code_json.verification_uri, init_code_json.user_code
				)),
			};

			let body = format!(
					"client_id={}&grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}",
					provider.client_id(),
					init_code_json.device_code
			);

			let mut interval_s = 5;
			while Timestamp::now() < expires_at {
				sleep(std::time::Duration::from_secs(interval_s)).await;

				match self.do_grant(provider, body.clone()).await {
					Ok(creds) => return Ok(creds),
					Err(AnyError::OAuthError(e)) if e.error == "slow_down" => {
						interval_s += 5; // https://www.rfc-editor.org/rfc/rfc8628#section-3.5
						trace!(self.log, "refresh poll failed, slowing down");
					}
					// Github returns a non-standard 429 to slow down
					Err(AnyError::StatusError(e)) if e.status_code == 429 => {
						interval_s += 5; // https://www.rfc-editor.org/rfc/rfc8628#section-3.5
						trace!(self.log, "refresh poll failed, slowing down");
					}
					Err(e) => {
						trace!(self.log, "refresh poll failed, retrying: {}", e);
					}
				}
			}
		}
	}

	/// Maintains the latest stored credential using supported silent refresh.
	/// Rejections require login; transient/provider/storage failures retry.
	pub async fn keep_token_alive(self) -> Result<(), AnyError> {
		let this = self.clone();
		let default_refresh = std::time::Duration::from_secs(60 * 60);
		let min_refresh = std::time::Duration::from_secs(10);

		let mut credential = this.get_credential().await?;
		let mut last_did_error = false;
		loop {
			let sleep_time = if last_did_error {
				min_refresh
			} else {
				match credential.expires_at {
					Some(d) => {
						let dur = d.duration_since(Timestamp::now());
						let nanos = dur.as_nanos() * 2 / 3;
						let scaled = SignedDuration::new(
							(nanos / 1_000_000_000) as i64,
							(nanos % 1_000_000_000) as i32,
						);
						if scaled.is_negative() {
							min_refresh
						} else {
							scaled.unsigned_abs()
						}
					}
					None => default_refresh,
				}
			};

			// to_std errors on negative duration, fall back to a 60s refresh
			#[cfg(test)]
			if let Some(sleeping) = &this.test_keepalive_sleeping {
				sleeping.notify_one();
			}
			tokio::time::sleep(sleep_time.max(min_refresh)).await;

			// Reread after sleeping and again before committing any refresh.
			// Never refresh the snapshot used only to calculate this sleep.
			let result = this.get_credential_silently(true).await;
			match result {
				Err(e @ AnyError::AuthenticationRequired(_)) => return Err(e),
				Err(e) => {
					warning!(this.log, "error refreshing token: {:?}", e);
					crate::tunnels::machine_status::emit_token_error(e.to_string());
					last_did_error = true;
					continue;
				}
				Ok(c) => {
					trace!(this.log, "token was successfully refreshed in keepalive");
					last_did_error = false;
					credential = c;
				}
			}
		}
	}
}

impl AuthorizationProvider for Auth {
	fn get_authorization(
		&self,
	) -> Pin<Box<dyn Future<Output = Result<Authorization, HttpError>> + Send + '_>> {
		Box::pin(async move {
			self.get_tunnel_authentication()
				.await
				.map_err(|e| HttpError::AuthorizationError(e.to_string()))
		})
	}
}

#[cfg(feature = "vscode-encrypt")]
static HOSTNAME: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
	gethostname::gethostname()
		.to_string_lossy()
		.bytes()
		.collect()
});

#[cfg(feature = "vscode-encrypt")]
fn encrypt(value: &str) -> String {
	vscode_encrypt::encrypt(&HOSTNAME, value.as_bytes()).expect("expected to encrypt")
}

#[cfg(feature = "vscode-encrypt")]
fn decrypt(value: &str) -> Option<String> {
	let b = vscode_encrypt::decrypt(&HOSTNAME, value).ok()?;
	String::from_utf8(b).ok()
}

#[cfg(not(feature = "vscode-encrypt"))]
fn encrypt(value: &str) -> String {
	value.to_owned()
}

#[cfg(not(feature = "vscode-encrypt"))]
fn decrypt(value: &str) -> Option<String> {
	Some(value.to_owned())
}

#[cfg(test)]
#[path = "auth_storage_reload_tests.rs"]
mod storage_reload_regression;

#[cfg(test)]
mod tests {
	use super::*;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	#[derive(Default)]
	struct TestBacking {
		value: Option<StoredCredential>,
		writes: usize,
		read_error: bool,
		store_error: bool,
	}

	#[derive(Clone)]
	struct TestStorage(Arc<std::sync::Mutex<TestBacking>>);

	impl StorageImplementation for TestStorage {
		fn read(&mut self) -> Result<Option<StoredCredential>, AnyError> {
			let backing = self.0.lock().unwrap();
			if backing.read_error {
				Err(wrap("", "synthetic storage unavailable").into())
			} else {
				Ok(backing.value.clone())
			}
		}

		fn store(&mut self, value: StoredCredential) -> Result<(), AnyError> {
			let mut backing = self.0.lock().unwrap();
			if backing.store_error {
				return Err(wrap("", "synthetic storage write unavailable").into());
			}
			backing.value = Some(value);
			backing.writes += 1;
			Ok(())
		}

		fn clear(&mut self) -> Result<(), AnyError> {
			self.0.lock().unwrap().value = None;
			Ok(())
		}
	}

	fn credential(token: &str) -> StoredCredential {
		StoredCredential {
			provider: AuthProvider::Microsoft,
			access_token: token.to_string(),
			refresh_token: None,
			expires_at: None,
		}
	}

	fn test_auth(value: Option<StoredCredential>) -> (Auth, TestStorage) {
		let backing = Arc::new(std::sync::Mutex::new(TestBacking {
			value: value.clone(),
			..TestBacking::default()
		}));
		(
			Auth {
				client: reqwest::Client::builder().no_proxy().build().unwrap(),
				log: log::Logger::test(),
				file_storage_path: PathBuf::new(),
				prefer_file_storage: false,
				storage: Arc::new(std::sync::Mutex::new(Some(CredentialStorage {
					storage: Box::new(TestStorage(backing.clone())),
					fallback_storage: None,
				}))),
				keyring_prefix: "auth-tests-unused".to_string(),
				forced_provider: None,
				non_interactive: true,
				authentication_required: Arc::new(AtomicBool::new(false)),
				refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
				storage_io_lock: Arc::new(tokio::sync::Mutex::new(())),
				test_endpoints: Some((
					"http://127.0.0.1:9".to_string(),
					"http://127.0.0.1:9".to_string(),
				)),
				test_request_timeout: Some(Duration::from_secs(2)),
				test_keepalive_sleeping: None,
			},
			TestStorage(backing),
		)
	}

	struct TestDirectory(PathBuf);

	impl TestDirectory {
		fn new() -> Self {
			let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
				.join("target")
				.join(format!("auth-test-{}", uuid::Uuid::new_v4()));
			std::fs::create_dir_all(&path).unwrap();
			Self(path)
		}
	}

	impl Drop for TestDirectory {
		fn drop(&mut self) {
			std::fs::remove_dir_all(&self.0).unwrap();
		}
	}

	async fn serve(
		responses: Vec<(u16, &'static str)>,
		mut on_request: impl FnMut(usize) + Send + 'static,
	) -> (String, tokio::task::JoinHandle<Vec<String>>) {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let uri = format!("http://{}", listener.local_addr().unwrap());
		let task = tokio::spawn(async move {
			let mut requests = Vec::new();
			for (index, (status, body)) in responses.into_iter().enumerate() {
				let (mut stream, _) = listener.accept().await.unwrap();
				let mut request = Vec::new();
				let mut buffer = [0; 1024];
				loop {
					let count = stream.read(&mut buffer).await.unwrap();
					assert_ne!(count, 0);
					request.extend_from_slice(&buffer[..count]);
					if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
						let headers = String::from_utf8_lossy(&request[..end]);
						let length = headers
							.lines()
							.find_map(|line| {
								line.to_ascii_lowercase()
									.strip_prefix("content-length: ")
									.and_then(|value| value.parse::<usize>().ok())
							})
							.unwrap_or(0);
						if request.len() >= end + 4 + length {
							break;
						}
					}
				}
				requests.push(String::from_utf8(request).unwrap());
				on_request(index);
				stream
					.write_all(
						format!(
							"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
							body.len()
						)
						.as_bytes(),
					)
					.await
					.unwrap();
			}
			requests
		});
		(uri, task)
	}

	fn endpoints(auth: &mut Auth, uri: String) {
		auth.test_endpoints = Some((uri.clone(), uri));
	}

	#[tokio::test]
	async fn missing_storage_and_provider_mismatch_have_distinct_outcomes() {
		let (mut auth, backing) = test_auth(None);
		let cloned = auth.clone();
		assert!(matches!(
			auth.get_credential().await,
			Err(AnyError::AuthenticationRequired(_))
		));
		assert!(cloned.authentication_required());

		backing.0.lock().unwrap().read_error = true;
		assert!(matches!(
			auth.get_credential().await,
			Err(AnyError::WrappedError(_))
		));
		assert!(!cloned.authentication_required());

		{
			let mut backing = backing.0.lock().unwrap();
			backing.read_error = false;
			backing.value = Some(credential("synthetic-login"));
		}
		auth.set_provider(AuthProvider::Github);
		assert!(matches!(
			auth.get_credential().await,
			Err(AnyError::AuthenticationRequired(_))
		));
		auth.set_provider(AuthProvider::Microsoft);
		assert!(auth.get_credential().await.is_ok());
		assert!(!cloned.authentication_required());
		assert_eq!(backing.0.lock().unwrap().writes, 0);
	}

	#[tokio::test]
	async fn github_only_401_requires_login_without_a_refresh_grant() {
		for status in [200, 401, 403, 429, 500, 503] {
			let (uri, server) = serve(vec![(status, "synthetic-private-response")], |_| {}).await;
			let mut stored = credential("synthetic-github");
			stored.provider = AuthProvider::Github;
			let (mut auth, backing) = test_auth(Some(stored));
			endpoints(&mut auth, uri);
			let result = auth.get_credential().await;
			match status {
				200 => assert!(result.is_ok()),
				401 => assert!(matches!(result, Err(AnyError::AuthenticationRequired(_)))),
				_ => {
					assert!(
						matches!(&result, Err(AnyError::StatusError(e)) if e.status_code == status)
					);
					assert!(!result
						.unwrap_err()
						.to_string()
						.contains("synthetic-private"));
				}
			}
			assert_eq!(auth.authentication_required(), status == 401);
			assert_eq!(backing.0.lock().unwrap().writes, 0);
			assert_eq!(server.await.unwrap().len(), 1);
		}
	}

	#[tokio::test]
	async fn silent_refresh_preserves_refresh_grant_and_encodes_it() {
		let (uri, server) = serve(
			vec![(
				200,
				r#"{"access_token":"synthetic-refreshed","expires_in":3600}"#,
			)],
			|_| {},
		)
		.await;
		let mut stored = credential("synthetic-expired");
		stored.expires_at = Some(Timestamp::now() - SignedDuration::from_secs(1));
		stored.refresh_token = Some("synthetic+grant&value".to_string());
		let (mut auth, backing) = test_auth(Some(stored));
		endpoints(&mut auth, uri);

		let refreshed = auth.get_credential().await.unwrap();
		assert_eq!(refreshed.access_token(), "synthetic-refreshed");
		assert_eq!(
			refreshed.refresh_token.as_deref(),
			Some("synthetic+grant&value")
		);
		assert_eq!(backing.0.lock().unwrap().writes, 1);
		assert!(server.await.unwrap()[0].contains("refresh_token=synthetic%2Bgrant%26value"));
	}

	#[tokio::test]
	async fn refresh_rejection_and_transient_errors_do_not_start_login() {
		for (status, body, rejected) in [
			(
				400,
				r#"{"error":"invalid_grant","error_description":"synthetic-private"}"#,
				true,
			),
			(
				400,
				r#"{"error":"interaction_required","error_description":"synthetic-private"}"#,
				false,
			),
			(
				400,
				r#"{"error":"invalid_grant","error_codes":[50076],"suberror":"basic_action"}"#,
				false,
			),
			(403, r#"{"error":"insufficient_scope"}"#, false),
			(429, r#"{"error":"invalid_grant"}"#, false),
			(500, r#"{"error":"invalid_grant"}"#, false),
		] {
			let (uri, server) = serve(vec![(status, body)], |_| {}).await;
			let mut stored = credential("synthetic-expired");
			stored.expires_at = Some(Timestamp::now() - SignedDuration::from_secs(1));
			stored.refresh_token = Some("synthetic-grant".to_string());
			let (mut auth, backing) = test_auth(Some(stored));
			endpoints(&mut auth, uri);
			let result = auth.get_credential().await;
			assert_eq!(
				matches!(&result, Err(AnyError::AuthenticationRequired(_))),
				rejected
			);
			assert_eq!(auth.authentication_required(), rejected);
			assert!(!result
				.unwrap_err()
				.to_string()
				.contains("synthetic-private"));
			assert_eq!(backing.0.lock().unwrap().writes, 0);
			assert_eq!(server.await.unwrap().len(), 1);
		}
	}

	#[tokio::test]
	async fn refresh_does_not_overwrite_login_replaced_during_request() {
		let mut expired = credential("synthetic-expired");
		expired.expires_at = Some(Timestamp::now() - SignedDuration::from_secs(1));
		expired.refresh_token = Some("synthetic-grant".to_string());
		let (mut auth, backing) = test_auth(Some(expired));
		let mut writer = backing.clone();
		let (uri, server) = serve(
			vec![(
				200,
				r#"{"access_token":"synthetic-stale-refresh","expires_in":3600}"#,
			)],
			move |_| {
				writer
					.store(credential("synthetic-external-login"))
					.unwrap()
			},
		)
		.await;
		endpoints(&mut auth, uri);
		assert_eq!(
			auth.get_credential().await.unwrap().access_token(),
			"synthetic-external-login"
		);
		assert_eq!(backing.0.lock().unwrap().writes, 1);
		server.await.unwrap();
	}

	#[tokio::test]
	async fn rejection_of_replaced_credential_uses_new_login() {
		let mut rejected = credential("synthetic-rejected");
		rejected.provider = AuthProvider::Github;
		let (mut auth, backing) = test_auth(Some(rejected));
		let mut writer = backing.clone();
		let (uri, server) = serve(vec![(401, "")], move |_| {
			writer
				.store(credential("synthetic-external-login"))
				.unwrap()
		})
		.await;
		endpoints(&mut auth, uri);
		assert_eq!(
			auth.get_credential().await.unwrap().access_token(),
			"synthetic-external-login"
		);
		assert!(!auth.authentication_required());
		server.await.unwrap();
	}

	#[tokio::test]
	async fn keepalive_checks_latest_storage_and_keeps_transient_errors_distinct() {
		let mut stale = credential("synthetic-stale");
		stale.provider = AuthProvider::Github;
		let (mut auth, mut backing) = test_auth(Some(stale));
		backing.store(credential("synthetic-replacement")).unwrap();
		assert_eq!(
			auth.get_credential_silently(true)
				.await
				.unwrap()
				.access_token(),
			"synthetic-replacement"
		);

		let mut rejected = credential("synthetic-rejected");
		rejected.provider = AuthProvider::Github;
		backing.store(rejected).unwrap();
		let (uri, server) = serve(vec![(429, "")], |_| {}).await;
		endpoints(&mut auth, uri);
		assert!(matches!(
			auth.get_credential_silently(true).await,
			Err(AnyError::StatusError(e)) if e.status_code == 429
		));
		server.await.unwrap();

		let (uri, server) = serve(vec![(401, "")], |_| {}).await;
		endpoints(&mut auth, uri);
		assert!(matches!(
			auth.keep_token_alive().await,
			Err(AnyError::AuthenticationRequired(_))
		));
		server.await.unwrap();
	}

	#[tokio::test(start_paused = true)]
	async fn keepalive_rereads_after_sleep_instead_of_refreshing_snapshot() {
		let (mut auth, mut backing) = test_auth(Some(credential("synthetic-initial")));
		let sleeping = Arc::new(tokio::sync::Notify::new());
		auth.test_keepalive_sleeping = Some(sleeping.clone());
		let observer = auth.clone();
		let keepalive = tokio::spawn(auth.keep_token_alive());
		sleeping.notified().await;
		backing.clear().unwrap();
		tokio::time::advance(Duration::from_secs(60 * 60)).await;
		assert!(matches!(
			keepalive.await.unwrap(),
			Err(AnyError::AuthenticationRequired(_))
		));
		assert!(observer.authentication_required());
		assert_eq!(backing.0.lock().unwrap().writes, 0);
	}

	#[tokio::test]
	async fn concurrent_refreshes_do_not_duplicate_writes() {
		let mut expired = credential("synthetic-expired");
		expired.expires_at = Some(Timestamp::now() - SignedDuration::from_secs(1));
		expired.refresh_token = Some("synthetic-grant".to_string());
		let (mut auth, backing) = test_auth(Some(expired));
		let (uri, server) = serve(
			vec![(
				200,
				r#"{"access_token":"synthetic-refreshed","expires_in":3600}"#,
			)],
			|_| {},
		)
		.await;
		endpoints(&mut auth, uri);
		let (first, second) = tokio::join!(auth.get_credential(), auth.get_credential());
		assert_eq!(first.unwrap(), second.unwrap());
		assert_eq!(backing.0.lock().unwrap().writes, 1);
		assert_eq!(server.await.unwrap().len(), 1);
	}

	#[tokio::test]
	async fn file_storage_rereads_and_backend_switches_are_authoritative() {
		let directory = TestDirectory::new();
		let path = directory.0.join("synthetic-token.json");
		let (auth, _) = test_auth(Some(credential("synthetic-native")));
		auth.with_storage(|storage| {
			storage.fallback_storage = Some(FileStorage(path.clone()));
		});
		assert_eq!(
			auth.get_credential().await.unwrap().access_token(),
			"synthetic-native"
		);
		let mut writer = FileStorage(path.clone());
		writer.store(credential("synthetic-file-a")).unwrap();
		assert_eq!(
			auth.get_credential().await.unwrap().access_token(),
			"synthetic-file-a"
		);
		writer.store(credential("synthetic-file-b")).unwrap();
		assert_eq!(
			auth.get_credential().await.unwrap().access_token(),
			"synthetic-file-b"
		);
		std::fs::write(&path, "synthetic-corrupt").unwrap();
		assert!(matches!(
			auth.get_credential().await,
			Err(AnyError::WrappedError(_))
		));
		assert!(!auth.authentication_required());
		std::fs::remove_file(&path).unwrap();
		assert_eq!(
			auth.get_credential().await.unwrap().access_token(),
			"synthetic-native"
		);
	}

	#[tokio::test]
	async fn native_write_fallback_can_be_replaced_by_an_external_login() {
		let directory = TestDirectory::new();
		let path = directory.0.join("synthetic-token.json");
		let (auth, backing) = test_auth(Some(credential("synthetic-native")));
		backing.0.lock().unwrap().store_error = true;
		auth.with_storage(|storage| {
			storage.fallback_storage = Some(FileStorage(path.clone()));
		});
		auth.store_credentials(credential("synthetic-fallback"))
			.unwrap();
		assert_eq!(
			auth.get_credential().await.unwrap().access_token(),
			"synthetic-fallback"
		);
		FileStorage(path)
			.store(credential("synthetic-external"))
			.unwrap();
		assert_eq!(
			auth.get_credential().await.unwrap().access_token(),
			"synthetic-external"
		);
	}

	#[tokio::test]
	async fn interactive_transient_failure_does_not_start_device_login() {
		let (uri, server) = serve(vec![(429, "")], |_| {}).await;
		let (mut auth, backing) = test_auth(Some(StoredCredential {
			provider: AuthProvider::Github,
			..credential("synthetic-throttled")
		}));
		auth.non_interactive = false;
		endpoints(&mut auth, uri);
		assert!(
			matches!(auth.get_credential().await, Err(AnyError::StatusError(error)) if error.status_code == 429)
		);
		assert_eq!(backing.0.lock().unwrap().writes, 0);
		assert_eq!(server.await.unwrap().len(), 1);
	}

	#[tokio::test]
	async fn explicit_login_reports_failed_persistence() {
		let (auth, backing) = test_auth(None);
		backing.0.lock().unwrap().store_error = true;
		assert!(auth
			.login(
				Some(AuthProvider::Microsoft),
				Some("synthetic-login".to_string()),
				None
			)
			.await
			.is_err());
		assert_eq!(backing.0.lock().unwrap().writes, 0);
	}

	#[tokio::test]
	async fn noninteractive_http_timeout_is_transient() {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let uri = format!("http://{}", listener.local_addr().unwrap());
		let (mut auth, _) = test_auth(Some(StoredCredential {
			provider: AuthProvider::Github,
			..credential("synthetic-timeout")
		}));
		endpoints(&mut auth, uri);
		auth.test_request_timeout = Some(Duration::from_millis(50));
		let server = tokio::spawn(async move {
			let (stream, _) = listener.accept().await.unwrap();
			std::future::pending::<()>().await;
			drop(stream);
		});
		assert!(matches!(
			auth.get_credential().await,
			Err(AnyError::WrappedError(_))
		));
		assert!(!auth.authentication_required());
		server.abort();
		assert!(server.await.unwrap_err().is_cancelled());
	}

	#[test]
	fn credential_expires_in_reports_positive_remaining_seconds() {
		let now = Timestamp::from_second(1_000_000).unwrap();
		let cases = [
			(None, None),
			(Some(now + SignedDuration::from_secs(3600)), Some(3600)),
			(Some(now + SignedDuration::from_millis(1500)), Some(1)),
			(Some(now + SignedDuration::from_millis(500)), None),
			(Some(now), None),
			(Some(now - SignedDuration::from_secs(60)), None),
		];
		let actual = cases.map(|(expires_at, _)| {
			StoredCredential {
				provider: AuthProvider::Microsoft,
				access_token: "test-token".to_string(),
				refresh_token: None,
				expires_at,
			}
			.expires_in(now)
		});

		assert_eq!(actual, cases.map(|(_, expected)| expected));
	}
}
