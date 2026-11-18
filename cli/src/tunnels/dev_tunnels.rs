/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
use super::protocol::{self, PortPrivacy, PortProtocol};
use crate::auth;
use crate::constants::{IS_INTERACTIVE_CLI, PROTOCOL_VERSION_TAG, TUNNEL_SERVICE_USER_AGENT};
use crate::log;
use crate::state::{LauncherPaths, PersistedState};
use crate::util::errors::{
	wrap, AnyError, CodeError, DevTunnelError, InvalidTunnelName, RelayCleanupError,
	TunnelCreationFailed, WrappedError,
};
use crate::util::input::prompt_placeholder;
use futures::future::BoxFuture;
use futures::{FutureExt, TryFutureExt};
use http::header::{HeaderName, HeaderValue};
use http::StatusCode;
use rand::prelude::IteratorRandom;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tunnels::connections::{
	ClientRelayHandle, ForwardedPortConnection, PortConnection, RelayTunnelClient, RelayTunnelHost,
};
use tunnels::contracts::{
	Tunnel, TunnelAccessControl, TunnelEndpoint, TunnelPort, PORT_TOKEN,
	TUNNEL_ACCESS_SCOPES_CONNECT, TUNNEL_PROTOCOL_AUTO,
};
use tunnels::management::{
	new_tunnel_management, HttpError, TunnelClientBuilder, TunnelLocator, TunnelManagementClient,
	TunnelRequestOptions, NO_REQUEST_OPTIONS,
};

static TUNNEL_COUNT_LIMIT_NAME: &str = "TunnelsPerUserPerLocation";
static TUNNEL_PORT_PROTOCOL_CONFLICT_DETAIL: &str = "The tunnel port protocol cannot be changed.";
static TUNNEL_SESSION_ID: LazyLock<uuid::Uuid> = LazyLock::new(uuid::Uuid::new_v4);
const TOKEN_REFRESH_TIMEOUT: Duration = Duration::from_secs(60);
const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(120);
const RELAY_CLEANUP_TIMEOUT: Duration = Duration::from_secs(20);

fn tunnel_correlation_id(
	log: &log::Logger,
	name: &str,
	value: Result<String, std::env::VarError>,
	fallback: uuid::Uuid,
) -> HeaderValue {
	let fallback = HeaderValue::from_str(&fallback.to_string()).unwrap();
	match value {
		Ok(value) if !value.is_empty() => match HeaderValue::from_str(&value) {
			Ok(id) => id,
			Err(error) => {
				warning!(log, "Invalid {}: {}", name, error);
				fallback
			}
		},
		Ok(_) => {
			warning!(log, "Invalid {}: empty correlation ID", name);
			fallback
		}
		Err(std::env::VarError::NotPresent) => fallback,
		Err(error) => {
			warning!(log, "Invalid {}: {}", name, error);
			fallback
		}
	}
}

fn tunnel_management_client(log: &log::Logger) -> TunnelClientBuilder {
	let session_id = tunnel_correlation_id(
		log,
		"VSCODE_TUNNEL_SESSION_ID",
		std::env::var("VSCODE_TUNNEL_SESSION_ID"),
		*TUNNEL_SESSION_ID,
	);
	let operation_id = tunnel_correlation_id(
		log,
		"VSCODE_TUNNEL_OPERATION_ID",
		std::env::var("VSCODE_TUNNEL_OPERATION_ID"),
		uuid::Uuid::new_v4(),
	);
	let mut client = new_tunnel_management(&TUNNEL_SERVICE_USER_AGENT);
	client.client(
		reqwest::Client::builder()
			.timeout(TOKEN_REFRESH_TIMEOUT)
			.build()
			.expect("expected to create tunnel management HTTP client"),
	);
	client.additional_headers(vec![
		(
			HeaderName::from_static("x-tunnels-vscode-session-id"),
			session_id,
		),
		(
			HeaderName::from_static("x-tunnels-vscode-client-operation-id"),
			operation_id,
		),
	]);
	client.additional_headers_provider(|| {
		vec![(
			HeaderName::from_static("x-tunnels-vscode-client-request-id"),
			HeaderValue::from_str(&uuid::Uuid::new_v4().to_string()).unwrap(),
		)]
	});
	client
}

#[allow(dead_code)]
mod tunnel_flags {
	use crate::{log, tunnels::wsl_detect::is_wsl_installed};

	pub const IS_WSL_INSTALLED: u32 = 1 << 0;
	pub const IS_WINDOWS: u32 = 1 << 1;
	pub const IS_LINUX: u32 = 1 << 2;
	pub const IS_MACOS: u32 = 1 << 3;

	/// Creates a flag string for the tunnel
	pub fn create(log: &log::Logger) -> String {
		let mut flags = 0;

		#[cfg(windows)]
		{
			flags |= IS_WINDOWS;
		}
		#[cfg(target_os = "linux")]
		{
			flags |= IS_LINUX;
		}
		#[cfg(target_os = "macos")]
		{
			flags |= IS_MACOS;
		}

		if is_wsl_installed(log) {
			flags |= IS_WSL_INSTALLED;
		}

		format!("_flag{flags}")
	}
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PersistedTunnel {
	pub name: String,
	pub id: String,
	pub cluster: String,
}

impl PersistedTunnel {
	pub fn into_locator(self) -> TunnelLocator {
		TunnelLocator::ID {
			cluster: self.cluster,
			id: self.id,
		}
	}
	pub fn locator(&self) -> TunnelLocator {
		TunnelLocator::ID {
			cluster: self.cluster.clone(),
			id: self.id.clone(),
		}
	}
}

#[allow(clippy::manual_async_fn)]
trait AccessTokenProvider: Send + Sync {
	/// Gets the current access token.
	fn refresh_token(&self) -> impl Future<Output = Result<String, WrappedError>> + Send;

	/// Maintains the stored credential by refreshing it against the service
	/// to ensure its stays current. Returns a future that should be polled and
	/// only completes if a refresh fails in a consistent way.
	fn keep_alive(&self) -> BoxFuture<'static, Result<(), AnyError>>;

	fn authentication_required(&self) -> bool {
		false
	}
}

/// Access token provider that provides a fixed token without refreshing.
struct StaticAccessTokenProvider(String);

impl StaticAccessTokenProvider {
	pub fn new(token: String) -> Self {
		Self(token)
	}
}

#[allow(clippy::manual_async_fn)]
impl AccessTokenProvider for StaticAccessTokenProvider {
	fn refresh_token(&self) -> impl Future<Output = Result<String, WrappedError>> + Send {
		async move { Ok(self.0.clone()) }
	}

	fn keep_alive(&self) -> BoxFuture<'static, Result<(), AnyError>> {
		futures::future::pending().boxed()
	}
}

/// Access token provider that looks up the token from the tunnels API.
struct LookupAccessTokenProvider {
	auth: auth::Auth,
	client: TunnelManagementClient,
	locator: TunnelLocator,
	log: log::Logger,
	initial_token: Arc<Mutex<Option<String>>>,
}

impl LookupAccessTokenProvider {
	pub fn new(
		auth: auth::Auth,
		client: TunnelManagementClient,
		locator: TunnelLocator,
		log: log::Logger,
		initial_token: Option<String>,
	) -> Self {
		Self {
			auth,
			client,
			locator,
			log,
			initial_token: Arc::new(Mutex::new(initial_token)),
		}
	}
}

#[allow(clippy::manual_async_fn)]
impl AccessTokenProvider for LookupAccessTokenProvider {
	fn refresh_token(&self) -> impl Future<Output = Result<String, WrappedError>> + Send {
		async move {
			if let Some(token) = self.initial_token.lock().unwrap().take() {
				return Ok(token);
			}

			let tunnel_lookup = self
				.client
				.get_tunnel(
					&self.locator,
					&TunnelRequestOptions {
						token_scopes: vec!["host".to_string()],
						..Default::default()
					},
				)
				.await;

			trace!(self.log, "Successfully refreshed access token");

			match tunnel_lookup {
				Ok(tunnel) => Ok(get_host_token_from_tunnel(&tunnel)),
				Err(e) => Err(wrap(e, "failed to lookup tunnel for host token")),
			}
		}
	}

	fn keep_alive(&self) -> BoxFuture<'static, Result<(), AnyError>> {
		let auth = self.auth.clone();
		auth.keep_token_alive().boxed()
	}

	fn authentication_required(&self) -> bool {
		self.auth.authentication_required()
	}
}

#[derive(Clone)]
pub struct DevTunnels {
	auth: auth::Auth,
	log: log::Logger,
	launcher_tunnel: PersistedState<Option<PersistedTunnel>>,
	client: TunnelManagementClient,
	tag: &'static str,
}

/// Representation of a tunnel returned from the `start` methods.
pub struct ActiveTunnel {
	/// Name of the tunnel
	pub name: String,
	/// Underlying dev tunnels ID
	pub id: String,
	manager: ActiveTunnelManager,
}

impl ActiveTunnel {
	/// Closes and unregisters the tunnel.
	pub async fn close(&mut self) -> Result<(), AnyError> {
		self.manager.kill().await?;
		Ok(())
	}

	/// Forwards a port to local connections.
	pub async fn add_port_direct(
		&mut self,
		port_number: u16,
	) -> Result<mpsc::UnboundedReceiver<ForwardedPortConnection>, AnyError> {
		let port = self.manager.add_port_direct(port_number).await?;
		Ok(port)
	}

	/// Forwards a port over TCP.
	pub async fn add_port_tcp(
		&self,
		port_number: u16,
		privacy: PortPrivacy,
		protocol: PortProtocol,
	) -> Result<(), AnyError> {
		self.manager
			.add_port_tcp(port_number, privacy, protocol)
			.await?;
		Ok(())
	}

	/// Removes a forwarded port TCP.
	pub async fn remove_port(&self, port_number: u16) -> Result<(), AnyError> {
		self.manager.remove_port(port_number).await?;
		Ok(())
	}

	/// Gets the template string for forming forwarded port web URIs..
	pub fn get_port_format(&self) -> Result<String, AnyError> {
		if let Some(details) = &*self.manager.endpoint_rx.borrow() {
			return details
				.as_ref()
				.map(|r| {
					r.port_uri_format
						.clone()
						.expect("expected to have port format")
				})
				.map_err(|e| e.clone().into());
		}

		Err(CodeError::NoTunnelEndpoint.into())
	}

	/// Gets the public URI on which a forwarded port can be access in browser.
	pub fn get_port_uri(&self, port: u16) -> Result<String, AnyError> {
		self.get_port_format()
			.map(|f| f.replace(PORT_TOKEN, &port.to_string()))
	}

	/// Gets an object to read the current tunnel status.
	pub fn status(&self) -> StatusLock {
		self.manager.get_status()
	}
}

const VSCODE_CLI_TUNNEL_TAG: &str = "vscode-server-launcher";
const VSCODE_CLI_FORWARDING_TAG: &str = "vscode-port-forward";
const OWNED_TUNNEL_TAGS: &[&str] = &[VSCODE_CLI_TUNNEL_TAG, VSCODE_CLI_FORWARDING_TAG];
const MAX_TUNNEL_NAME_LENGTH: usize = 20;

fn get_host_token_from_tunnel(tunnel: &Tunnel) -> String {
	tunnel
		.access_tokens
		.as_ref()
		.expect("expected to have access tokens")
		.get("host")
		.expect("expected to have host token")
		.to_string()
}

fn is_valid_name(name: &str) -> Result<(), InvalidTunnelName> {
	if name.len() > MAX_TUNNEL_NAME_LENGTH {
		return Err(InvalidTunnelName(format!(
			"Names cannot be longer than {MAX_TUNNEL_NAME_LENGTH} characters. Please try a different name."
		)));
	}

	let re = Regex::new(r"^([\w-]+)$").unwrap();

	if !re.is_match(name) {
		return Err(InvalidTunnelName(
            "Names can only contain letters, numbers, and '-'. Spaces, commas, and all other special characters are not allowed. Please try a different name.".to_string()
        ));
	}

	Ok(())
}

static HOST_TUNNEL_REQUEST_OPTIONS: LazyLock<TunnelRequestOptions> =
	LazyLock::new(|| TunnelRequestOptions {
		include_ports: true,
		token_scopes: vec!["host".to_string()],
		..Default::default()
	});

/// Structure optionally passed into `start_existing_tunnel` to forward an existing tunnel.
#[derive(Clone, Debug)]
pub struct ExistingTunnel {
	/// Name you'd like to assign preexisting tunnel to use to connect to the VS Code Server
	pub tunnel_name: Option<String>,

	/// Token to authenticate and use preexisting tunnel
	pub host_token: String,

	/// Id of preexisting tunnel to use to connect to the VS Code Server
	pub tunnel_id: String,

	/// Cluster of preexisting tunnel to use to connect to the VS Code Server
	pub cluster: String,
}

impl DevTunnels {
	/// Creates a new DevTunnels client used for port forwarding.
	pub fn new_port_forwarding(
		log: &log::Logger,
		auth: auth::Auth,
		paths: &LauncherPaths,
	) -> DevTunnels {
		let mut client = tunnel_management_client(log);
		client.authorization_provider(auth.clone());

		DevTunnels {
			auth,
			log: log.clone(),
			client: client.into(),
			launcher_tunnel: PersistedState::new(paths.root().join("port_forwarding_tunnel.json")),
			tag: VSCODE_CLI_FORWARDING_TAG,
		}
	}

	/// Creates a new DevTunnels client used for the Remote Tunnels extension to access the VS Code Server.
	pub fn new_remote_tunnel(
		log: &log::Logger,
		auth: auth::Auth,
		paths: &LauncherPaths,
	) -> DevTunnels {
		let mut client = tunnel_management_client(log);
		client.authorization_provider(auth.clone());

		DevTunnels {
			auth,
			log: log.clone(),
			client: client.into(),
			launcher_tunnel: PersistedState::new(paths.root().join("code_tunnel.json")),
			tag: VSCODE_CLI_TUNNEL_TAG,
		}
	}

	pub async fn remove_tunnel(&mut self) -> Result<(), AnyError> {
		let tunnel = match self.launcher_tunnel.load() {
			Some(t) => t,
			None => {
				return Ok(());
			}
		};

		self.client
			.delete_tunnel(&tunnel.into_locator(), NO_REQUEST_OPTIONS)
			.await
			.map_err(|e| wrap(e, "failed to execute `tunnel delete`"))?;

		self.launcher_tunnel.save(None)?;
		Ok(())
	}

	/// Renames the current tunnel to the new name.
	pub async fn rename_tunnel(&mut self, name: &str) -> Result<(), AnyError> {
		self.update_tunnel_name(self.launcher_tunnel.load(), name)
			.await
			.map(|_| ())
	}

	/// Connects to a tunnel by name as a client, returning a raw connection
	/// to the tunnel's agent host port. The caller is responsible for doing
	/// the WebSocket upgrade over the returned stream.
	///
	/// The returned [`ClientRelayHandle`] must be kept alive for the duration
	/// of the connection; dropping it closes the underlying SSH session.
	pub async fn connect_to_tunnel_port(
		&mut self,
		name: &str,
		port: u16,
	) -> Result<(PortConnection, ClientRelayHandle), AnyError> {
		let tunnel = self.get_tunnel_with_connect_scope(name).await?;

		let endpoint = tunnel.endpoints.first().ok_or_else(|| {
			DevTunnelError(format!(
				"Tunnel '{name}' has no active endpoint (is the host running?)",
			))
		})?;

		let connect_token = tunnel
			.access_tokens
			.as_ref()
			.and_then(|t| t.get("connect"))
			.ok_or_else(|| {
				DevTunnelError(format!(
					"No connect-scoped access token for tunnel '{name}'",
				))
			})?;

		let client = RelayTunnelClient::new(self.client.clone());
		let handle = client
			.connect(endpoint, connect_token)
			.await
			.map_err(|e| wrap(e, "failed to connect to tunnel relay"))?;

		let port_conn = handle
			.connect_to_port(port)
			.await
			.map_err(|e| wrap(e, format!("failed to connect to port {port} on tunnel")))?;

		Ok((port_conn, handle))
	}

	/// Looks up a tunnel by name with connect-scoped access token.
	async fn get_tunnel_with_connect_scope(&self, name: &str) -> Result<Tunnel, AnyError> {
		let existing: Vec<Tunnel> = self
			.client
			.list_all_tunnels(&TunnelRequestOptions {
				labels: vec![self.tag.to_string(), name.to_string()],
				require_all_labels: true,
				limit: 1,
				..Default::default()
			})
			.await
			.map_err(|e| wrap(e, "failed to list tunnels"))?;

		let tunnel = match existing.into_iter().next() {
			Some(t) => t,
			None => {
				return Err(DevTunnelError(format!("No tunnel found with name '{name}'")).into())
			}
		};

		let loc = TunnelLocator::try_from(&tunnel).unwrap();
		self.client
			.get_tunnel(
				&loc,
				&TunnelRequestOptions {
					include_ports: true,
					token_scopes: vec!["connect".to_string()],
					..Default::default()
				},
			)
			.await
			.map_err(|e| wrap(e, "failed to lookup tunnel").into())
	}

	/// Updates the name of the existing persisted tunnel to the new name.
	/// Gracefully creates a new tunnel if the previous one was deleted.
	async fn update_tunnel_name(
		&mut self,
		persisted: Option<PersistedTunnel>,
		name: &str,
	) -> Result<(Tunnel, PersistedTunnel), AnyError> {
		let name = name.to_ascii_lowercase();

		let (mut full_tunnel, mut persisted, is_new) = match persisted {
			Some(persisted) => {
				debug!(
					self.log,
					"Found a persisted tunnel, seeing if the name matches..."
				);
				self.get_or_create_tunnel(persisted, Some(&name), NO_REQUEST_OPTIONS)
					.await
			}
			None => {
				debug!(self.log, "Creating a new tunnel with the requested name");
				self.create_tunnel(&name, NO_REQUEST_OPTIONS)
					.await
					.map(|(pt, t)| (t, pt, true))
			}
		}?;

		let desired_tags = self.get_labels(&name);
		if is_new || vec_eq_as_set(&full_tunnel.labels, &desired_tags) {
			return Ok((full_tunnel, persisted));
		}

		debug!(self.log, "Tunnel name changed, applying updates...");

		full_tunnel.labels = desired_tags;

		let updated_tunnel = self
			.client
			.update_tunnel(&full_tunnel, NO_REQUEST_OPTIONS)
			.await
			.map_err(|e| wrap(e, "failed to rename tunnel"))?;

		persisted.name = name;
		self.launcher_tunnel.save(Some(persisted.clone()))?;

		Ok((updated_tunnel, persisted))
	}

	/// Gets the persisted tunnel from the service, or creates a new one.
	/// If `create_with_new_name` is given, the new tunnel has that name
	/// instead of the one previously persisted.
	async fn get_or_create_tunnel(
		&mut self,
		persisted: PersistedTunnel,
		create_with_new_name: Option<&str>,
		options: &TunnelRequestOptions,
	) -> Result<(Tunnel, PersistedTunnel, /* is_new */ bool), AnyError> {
		let tunnel_lookup = self.client.get_tunnel(&persisted.locator(), options).await;

		match tunnel_lookup {
			Ok(ft) => Ok((ft, persisted, false)),
			Err(HttpError::ResponseError(e))
				if e.status_code.as_u16() == StatusCode::NOT_FOUND.as_u16()
					|| e.status_code.as_u16() == StatusCode::FORBIDDEN.as_u16() =>
			{
				let (persisted, tunnel) = self
					.create_tunnel(create_with_new_name.unwrap_or(&persisted.name), options)
					.await?;
				Ok((tunnel, persisted, true))
			}
			Err(e) => Err(wrap(e, "failed to lookup tunnel").into()),
		}
	}

	/// Starts a new tunnel for the code server on the port. Unlike `start_new_tunnel`,
	/// this attempts to reuse or create a tunnel of a preferred name or of a generated friendly tunnel name.
	pub async fn start_new_launcher_tunnel(
		&mut self,
		preferred_name: Option<&str>,
		use_random_name: bool,
		preserve_ports: &[u16],
	) -> Result<ActiveTunnel, AnyError> {
		let (mut tunnel, persisted) = match self.launcher_tunnel.load() {
			Some(mut persisted) => {
				if let Some(preferred_name) = preferred_name.map(|n| n.to_ascii_lowercase()) {
					if persisted.name.to_ascii_lowercase() != preferred_name {
						(_, persisted) = self
							.update_tunnel_name(Some(persisted), &preferred_name)
							.await?;
					}
				}

				let (tunnel, persisted, _) = self
					.get_or_create_tunnel(persisted, None, &HOST_TUNNEL_REQUEST_OPTIONS)
					.await?;
				(tunnel, persisted)
			}
			None => {
				debug!(self.log, "No code server tunnel found, creating new one");
				let name = self
					.get_name_for_tunnel(preferred_name, use_random_name)
					.await?;
				let (persisted, full_tunnel) = self
					.create_tunnel(&name, &HOST_TUNNEL_REQUEST_OPTIONS)
					.await?;
				(full_tunnel, persisted)
			}
		};

		tunnel = self
			.sync_tunnel_tags(
				&self.client,
				&persisted.name,
				tunnel,
				&HOST_TUNNEL_REQUEST_OPTIONS,
			)
			.await?;

		let locator = TunnelLocator::try_from(&tunnel).unwrap();
		let host_token = get_host_token_from_tunnel(&tunnel);

		for port_to_delete in tunnel
			.ports
			.iter()
			.filter(|p: &&TunnelPort| !preserve_ports.contains(&p.port_number))
		{
			let output_fut = self.client.delete_tunnel_port(
				&locator,
				port_to_delete.port_number,
				NO_REQUEST_OPTIONS,
			);
			output_fut
				.await
				.map_err(|e| wrap(e, "failed to delete port"))?;
		}

		// cleanup any old trailing tunnel endpoints
		for endpoint in tunnel.endpoints {
			let fut = self.client.delete_tunnel_endpoints(
				&locator,
				&endpoint.host_id,
				NO_REQUEST_OPTIONS,
			);

			fut.await
				.map_err(|e| wrap(e, "failed to prune tunnel endpoint"))?;
		}

		self.start_tunnel(
			locator.clone(),
			&persisted,
			self.client.clone(),
			LookupAccessTokenProvider::new(
				self.auth.clone(),
				self.client.clone(),
				locator,
				self.log.clone(),
				Some(host_token),
			),
		)
		.await
	}

	async fn create_tunnel(
		&mut self,
		name: &str,
		options: &TunnelRequestOptions,
	) -> Result<(PersistedTunnel, Tunnel), AnyError> {
		info!(self.log, "Creating tunnel with the name: {}", name);

		let tunnel = match self.get_existing_tunnel_with_name(name).await? {
			Some(e) => {
				if tunnel_has_host_connection(&e) {
					return Err(CodeError::TunnelActiveAndInUse(name.to_string()).into());
				}

				let loc = TunnelLocator::try_from(&e).unwrap();
				info!(self.log, "Adopting existing tunnel (ID={:?})", loc);
				self.client
					.get_tunnel(&loc, &HOST_TUNNEL_REQUEST_OPTIONS)
					.await
					.map_err(|e| wrap(e, "failed to lookup tunnel"))?
			}
			None => loop {
				let result = self
					.client
					.create_tunnel(
						Tunnel {
							labels: self.get_labels(name),
							..Default::default()
						},
						options,
					)
					.await;

				match result {
					Err(HttpError::ResponseError(e))
						if e.status_code.as_u16() == StatusCode::TOO_MANY_REQUESTS.as_u16() =>
					{
						if let Some(d) = e.get_details() {
							let detail = d.detail.unwrap_or_else(|| "unknown".to_string());
							if detail.contains(TUNNEL_COUNT_LIMIT_NAME)
								&& self.try_recycle_tunnel().await?
							{
								continue;
							}

							return Err(AnyError::from(TunnelCreationFailed(
								name.to_string(),
								detail,
							)));
						}

						return Err(AnyError::from(TunnelCreationFailed(
								name.to_string(),
								"You have exceeded a limit for the port forwarding service. Please remove other machines before trying to add this machine.".to_string(),
							)));
					}
					Err(e) => {
						return Err(AnyError::from(TunnelCreationFailed(
							name.to_string(),
							format!("{e:?}"),
						)))
					}
					Ok(t) => break t,
				}
			},
		};

		let pt = PersistedTunnel {
			cluster: tunnel.cluster_id.clone().unwrap(),
			id: tunnel.tunnel_id.clone().unwrap(),
			name: name.to_string(),
		};

		self.launcher_tunnel.save(Some(pt.clone()))?;
		Ok((pt, tunnel))
	}

	/// Gets the expected tunnel tags
	fn get_labels(&self, name: &str) -> Vec<String> {
		vec![
			name.to_string(),
			PROTOCOL_VERSION_TAG.to_string(),
			self.tag.to_string(),
			tunnel_flags::create(&self.log),
		]
	}

	/// Ensures the tunnel contains a tag for the current PROTOCOL_VERSION, and no
	/// other version tags.
	async fn sync_tunnel_tags(
		&self,
		client: &TunnelManagementClient,
		name: &str,
		tunnel: Tunnel,
		options: &TunnelRequestOptions,
	) -> Result<Tunnel, AnyError> {
		let new_labels = self.get_labels(name);
		if vec_eq_as_set(&tunnel.labels, &new_labels) {
			return Ok(tunnel);
		}

		debug!(
			self.log,
			"Updating tunnel tags {} -> {}",
			tunnel.labels.join(", "),
			new_labels.join(", ")
		);

		let tunnel_update = Tunnel {
			labels: new_labels,
			tunnel_id: tunnel.tunnel_id.clone(),
			cluster_id: tunnel.cluster_id.clone(),
			..Default::default()
		};

		let result = client.update_tunnel(&tunnel_update, options).await;

		result.map_err(|e| wrap(e, "tunnel tag update failed").into())
	}

	/// Tries to delete an unused tunnel, and then creates a tunnel with the
	/// given `new_name`.
	async fn try_recycle_tunnel(&mut self) -> Result<bool, AnyError> {
		trace!(
			self.log,
			"Tunnel limit hit, trying to recycle an old tunnel"
		);

		let existing_tunnels = self.list_tunnels_with_tag(OWNED_TUNNEL_TAGS).await?;

		let recyclable = existing_tunnels
			.iter()
			.filter(|t| !tunnel_has_host_connection(t))
			.choose(&mut rand::thread_rng());

		match recyclable {
			Some(tunnel) => {
				trace!(self.log, "Recycling tunnel ID {:?}", tunnel.tunnel_id);
				self.client
					.delete_tunnel(&tunnel.try_into().unwrap(), NO_REQUEST_OPTIONS)
					.await
					.map_err(|e| wrap(e, "failed to execute `tunnel delete`"))?;
				Ok(true)
			}
			None => {
				trace!(self.log, "No tunnels available to recycle");
				Ok(false)
			}
		}
	}

	async fn list_tunnels_with_tag(
		&mut self,
		tags: &[&'static str],
	) -> Result<Vec<Tunnel>, AnyError> {
		let tunnels = self
			.client
			.list_all_tunnels(&TunnelRequestOptions {
				labels: tags.iter().map(|t| t.to_string()).collect(),
				..Default::default()
			})
			.await
			.map_err(|e| wrap(e, "error listing current tunnels"))?;

		Ok(tunnels)
	}

	async fn get_existing_tunnel_with_name(&self, name: &str) -> Result<Option<Tunnel>, AnyError> {
		let existing: Vec<Tunnel> = self
			.client
			.list_all_tunnels(&TunnelRequestOptions {
				labels: vec![self.tag.to_string(), name.to_string()],
				require_all_labels: true,
				limit: 1,
				include_ports: true,
				token_scopes: vec!["host".to_string()],
				..Default::default()
			})
			.await
			.map_err(|e| wrap(e, "failed to list existing tunnels"))?;

		Ok(existing.into_iter().next())
	}

	fn get_placeholder_name() -> String {
		let mut n = clean_hostname_for_tunnel(&gethostname::gethostname().to_string_lossy());
		n.make_ascii_lowercase();
		n.truncate(MAX_TUNNEL_NAME_LENGTH);
		n
	}

	async fn get_name_for_tunnel(
		&mut self,
		preferred_name: Option<&str>,
		mut use_random_name: bool,
	) -> Result<String, AnyError> {
		let existing_tunnels = self.list_tunnels_with_tag(&[self.tag]).await?;
		let is_name_free = |n: &str| {
			!existing_tunnels
				.iter()
				.any(|v| tunnel_has_host_connection(v) && v.labels.iter().any(|t| t == n))
		};

		if let Some(machine_name) = preferred_name {
			let name = machine_name.to_ascii_lowercase();
			if let Err(e) = is_valid_name(&name) {
				info!(self.log, "{} is an invalid name", e);
				return Err(AnyError::from(wrap(e, "invalid name")));
			}
			if is_name_free(&name) {
				return Ok(name);
			}
			info!(
				self.log,
				"{} is already taken, using a random name instead", &name
			);
			use_random_name = true;
		}

		let mut placeholder_name = Self::get_placeholder_name();
		if !is_name_free(&placeholder_name) {
			for i in 2.. {
				let fixed_name = format!("{placeholder_name}{i}");
				if is_name_free(&fixed_name) {
					placeholder_name = fixed_name;
					break;
				}
			}
		}

		if use_random_name || !*IS_INTERACTIVE_CLI {
			return Ok(placeholder_name);
		}

		loop {
			let mut name = prompt_placeholder(
				"What would you like to call this machine?",
				&placeholder_name,
			)?;

			name.make_ascii_lowercase();

			if let Err(e) = is_valid_name(&name) {
				info!(self.log, "{}", e);
				continue;
			}

			if is_name_free(&name) {
				return Ok(name);
			}

			info!(self.log, "The name {} is already in use", name);
		}
	}

	/// Hosts an existing tunnel, where the tunnel ID and host token are given.
	pub async fn start_existing_tunnel(
		&mut self,
		tunnel: ExistingTunnel,
	) -> Result<ActiveTunnel, AnyError> {
		let tunnel_details = PersistedTunnel {
			name: match tunnel.tunnel_name {
				Some(n) => n,
				None => Self::get_placeholder_name(),
			},
			id: tunnel.tunnel_id,
			cluster: tunnel.cluster,
		};

		let mut mgmt = self.client.build();
		mgmt.authorization(tunnels::management::Authorization::Tunnel(
			tunnel.host_token.clone(),
		));

		let client = mgmt.into();
		self.sync_tunnel_tags(
			&client,
			&tunnel_details.name,
			Tunnel {
				cluster_id: Some(tunnel_details.cluster.clone()),
				tunnel_id: Some(tunnel_details.id.clone()),
				..Default::default()
			},
			&HOST_TUNNEL_REQUEST_OPTIONS,
		)
		.await?;

		self.start_tunnel(
			tunnel_details.locator(),
			&tunnel_details,
			client,
			StaticAccessTokenProvider::new(tunnel.host_token),
		)
		.await
	}

	async fn start_tunnel(
		&mut self,
		locator: TunnelLocator,
		tunnel_details: &PersistedTunnel,
		client: TunnelManagementClient,
		access_token: impl AccessTokenProvider + 'static,
	) -> Result<ActiveTunnel, AnyError> {
		let mut manager = ActiveTunnelManager::new(self.log.clone(), client, locator, access_token);

		let endpoint_result = manager.get_endpoint().await;

		let endpoint = match endpoint_result {
			Ok(endpoint) => endpoint,
			Err(e) => {
				error!(self.log, "Error connecting to tunnel endpoint: {}", e);
				manager.kill().await?;
				return Err(e);
			}
		};

		debug!(self.log, "Connected to tunnel endpoint: {:?}", endpoint);

		Ok(ActiveTunnel {
			name: tunnel_details.name.clone(),
			id: tunnel_details.id.clone(),
			manager,
		})
	}
}

#[derive(Clone)]
pub struct StatusLock(watch::Sender<protocol::singleton::Status>);

impl Default for StatusLock {
	fn default() -> Self {
		Self(watch::channel(protocol::singleton::Status::default()).0)
	}
}

impl StatusLock {
	pub(super) fn succeed(&self) {
		self.0.send_modify(|status| {
			status.tunnel = protocol::singleton::TunnelState::Connected;
			status.last_connected_at = Some(jiff::Timestamp::now());
			status.recovery = None;
		});
	}

	pub(super) fn fail(&self, reason: String) {
		self.fail_with_recovery(reason, protocol::singleton::RecoveryState::Retrying);
	}

	pub(super) fn fail_with_recovery(
		&self,
		reason: String,
		recovery: protocol::singleton::RecoveryState,
	) {
		self.0.send_modify(|status| {
			if let protocol::singleton::TunnelState::Connected = status.tunnel {
				status.last_disconnected_at = Some(jiff::Timestamp::now());
				status.tunnel = protocol::singleton::TunnelState::Disconnected;
			}
			status.last_fail_reason = Some(reason);
			status.recovery = Some(recovery);
		});
	}

	fn disconnect_if_connected(&self) {
		self.0.send_if_modified(|status| {
			if matches!(status.tunnel, protocol::singleton::TunnelState::Connected) {
				status.tunnel = protocol::singleton::TunnelState::Disconnected;
				status.last_disconnected_at = Some(jiff::Timestamp::now());
				status.last_fail_reason = Some("Tunnel relay task stopped".to_string());
				status.recovery = Some(protocol::singleton::RecoveryState::Failed);
				true
			} else {
				false
			}
		});
	}

	pub fn read(&self) -> protocol::singleton::Status {
		self.0.borrow().clone()
	}

	pub(super) fn subscribe(&self) -> watch::Receiver<protocol::singleton::Status> {
		self.0.subscribe()
	}

	fn recovering(&self, recovery: protocol::singleton::RecoveryState) {
		self.0
			.send_modify(|status| status.recovery = Some(recovery));
	}

	#[cfg(test)]
	pub(super) fn connect_for_regression(&self) {
		self.succeed();
	}
}

struct TunnelStatusGuard(StatusLock);

impl Drop for TunnelStatusGuard {
	fn drop(&mut self) {
		self.0.disconnect_if_connected();
	}
}

struct TokenKeepAliveTask(tokio::task::JoinHandle<Result<(), AnyError>>);

impl Drop for TokenKeepAliveTask {
	fn drop(&mut self) {
		self.0.abort();
	}
}

fn keepalive_result(
	result: Result<Result<(), AnyError>, tokio::task::JoinError>,
) -> Result<(), AnyError> {
	result.unwrap_or_else(|_| {
		Err(wrap("", "Credential keep-alive worker stopped unexpectedly").into())
	})
}

fn keepalive_failure(
	error: AnyError,
	authentication_required: bool,
) -> (WrappedError, protocol::singleton::RecoveryState) {
	if authentication_required || matches!(&error, AnyError::AuthenticationRequired(_)) {
		(
			wrap(error, "access token is no longer valid"),
			protocol::singleton::RecoveryState::AuthenticationRequired,
		)
	} else {
		(
			wrap(error, "Credential maintenance failed"),
			protocol::singleton::RecoveryState::Retrying,
		)
	}
}

struct ActiveTunnelManager {
	log: log::Logger,
	close_tx: Option<mpsc::Sender<()>>,
	endpoint_rx: watch::Receiver<Option<Result<TunnelEndpoint, WrappedError>>>,
	relay: Arc<tokio::sync::Mutex<RelayTunnelHost>>,
	status: StatusLock,
	worker: Option<tokio::task::JoinHandle<()>>,
}

impl ActiveTunnelManager {
	pub fn new(
		log: log::Logger,
		mgmt: TunnelManagementClient,
		locator: TunnelLocator,
		access_token: impl AccessTokenProvider + 'static,
	) -> ActiveTunnelManager {
		let (endpoint_tx, endpoint_rx) = watch::channel(None);
		let (close_tx, close_rx) = mpsc::channel(1);

		let relay = Arc::new(tokio::sync::Mutex::new(RelayTunnelHost::new(locator, mgmt)));
		let relay_spawned = relay.clone();

		let status = StatusLock::default();

		let status_spawned = status.clone();
		let endpoint_supervisor = endpoint_tx.clone();
		let manager_log = log.clone();
		let worker = tokio::spawn(async move {
			let result = AssertUnwindSafe(ActiveTunnelManager::spawn_tunnel(
				log.clone(),
				relay_spawned,
				close_rx,
				endpoint_tx,
				access_token,
				status_spawned.clone(),
			))
			.catch_unwind()
			.await;
			if result.is_err() {
				let message = "Tunnel relay worker panicked; refusing an unverified replacement";
				error!(log, "{}", message);
				status_spawned.fail_with_recovery(
					message.to_string(),
					protocol::singleton::RecoveryState::Failed,
				);
				endpoint_supervisor.send_replace(Some(Err(wrap("", message))));
			}
		});

		ActiveTunnelManager {
			log: manager_log,
			endpoint_rx,
			relay,
			close_tx: Some(close_tx),
			status,
			worker: Some(worker),
		}
	}

	/// Gets a copy of the current tunnel status information
	pub fn get_status(&self) -> StatusLock {
		self.status.clone()
	}

	/// Adds a port for TCP/IP forwarding.
	pub async fn add_port_tcp(
		&self,
		port_number: u16,
		privacy: PortPrivacy,
		protocol: PortProtocol,
	) -> Result<(), WrappedError> {
		let relay = self.relay.lock().await;
		let port = TunnelPort {
			port_number,
			protocol: Some(protocol.to_contract_str().to_string()),
			access_control: Some(privacy_to_tunnel_acl(privacy)),
			..Default::default()
		};

		match relay.add_port(&port).await {
			Ok(()) => {}
			Err(error) if is_tunnel_port_protocol_conflict(&error) => {
				relay
					.remove_port(port_number)
					.await
					.map_err(|e| wrap(e, "error replacing port protocol in relay"))?;
				relay
					.add_port(&port)
					.await
					.map_err(|e| wrap(e, "error adding port to relay"))?;
			}
			Err(error) => return Err(wrap(error, "error adding port to relay")),
		}

		Ok(())
	}

	/// Adds a port for TCP/IP forwarding.
	pub async fn add_port_direct(
		&self,
		port_number: u16,
	) -> Result<mpsc::UnboundedReceiver<ForwardedPortConnection>, WrappedError> {
		let relay = self.relay.lock().await;
		let port = TunnelPort {
			port_number,
			protocol: Some(TUNNEL_PROTOCOL_AUTO.to_owned()),
			access_control: Some(privacy_to_tunnel_acl(PortPrivacy::Private)),
			..Default::default()
		};

		match relay.add_port_raw(&port).await {
			Ok(receiver) => Ok(receiver),
			Err(error) if is_tunnel_port_protocol_conflict(&error) => {
				relay
					.remove_port(port_number)
					.await
					.map_err(|e| wrap(e, "error replacing port protocol in relay"))?;
				relay
					.add_port_raw(&port)
					.await
					.map_err(|e| wrap(e, "error adding port to relay"))
			}
			Err(error) => Err(wrap(error, "error adding port to relay")),
		}
	}

	/// Removes a port from TCP/IP forwarding.
	pub async fn remove_port(&self, port_number: u16) -> Result<(), WrappedError> {
		self.relay
			.lock()
			.await
			.remove_port(port_number)
			.await
			.map_err(|e| wrap(e, "error remove port from relay"))
	}

	/// Gets the most recent details from the tunnel process. Returns None if
	/// the process exited before providing details.
	pub async fn get_endpoint(&mut self) -> Result<TunnelEndpoint, AnyError> {
		loop {
			if let Some(details) = &*self.endpoint_rx.borrow() {
				return details.clone().map_err(AnyError::from);
			}

			if self.endpoint_rx.changed().await.is_err() {
				return Err(DevTunnelError("tunnel creation cancelled".to_string()).into());
			}
		}
	}

	/// Kills the process, and waits for it to exit.
	/// See https://tokio.rs/tokio/topics/shutdown#waiting-for-things-to-finish-shutting-down for how this works
	pub async fn kill(&mut self) -> Result<(), AnyError> {
		self.status.disconnect_if_connected();
		if let Some(tx) = self.close_tx.take() {
			drop(tx);
		}

		if let Some(worker) = self.worker.as_mut() {
			let result = tokio::time::timeout(RELAY_CLEANUP_TIMEOUT, worker)
				.await
				.map_err(|e| {
					self.status
						.recovering(protocol::singleton::RecoveryState::CleanupBlocked);
					RelayCleanupError(wrap(e, "Timed out waiting for relay cleanup"))
				})?;
			self.worker.take();
			result.map_err(|e| RelayCleanupError(wrap(e, "error joining relay worker")))?;
		}

		if matches!(
			self.status.read().recovery,
			Some(
				protocol::singleton::RecoveryState::Failed
					| protocol::singleton::RecoveryState::CleanupBlocked
			)
		) {
			return Err(
				RelayCleanupError(wrap("", "relay worker could not verify cleanup")).into(),
			);
		}

		// The worker has confirmed the connection is closed. An unavailable
		// management API must not prevent recovery of a disconnected relay.
		match tokio::time::timeout(RELAY_CLEANUP_TIMEOUT, async {
			self.relay.lock().await.unregister().await
		})
		.await
		{
			Ok(Ok(_)) => {}
			Ok(Err(error)) => warning!(
				self.log,
				"Relay closed but endpoint unregister failed: {}",
				error
			),
			Err(error) => warning!(
				self.log,
				"Relay closed but endpoint unregister timed out: {}",
				error
			),
		}

		Ok(())
	}

	async fn spawn_tunnel(
		log: log::Logger,
		relay: Arc<tokio::sync::Mutex<RelayTunnelHost>>,
		close_rx: mpsc::Receiver<()>,
		endpoint_tx: watch::Sender<Option<Result<TunnelEndpoint, WrappedError>>>,
		access_token_provider: impl AccessTokenProvider + 'static,
		status: StatusLock,
	) {
		Self::run_tunnel(
			log,
			move |access_token: String| {
				let relay = relay.clone();
				async move {
					relay
						.lock()
						.await
						.connect(&access_token)
						.await
						.map_err(|e| wrap(e, "error connecting to tunnel"))
				}
				.boxed()
			},
			|handle: &tunnels::connections::RelayHandle| handle.endpoint().clone(),
			|handle: tunnels::connections::RelayHandle| async move {
				handle
					.close()
					.await
					.map_err(|e| wrap(e, "error closing relay"))
			},
			close_rx,
			endpoint_tx,
			access_token_provider,
			status,
		)
		.await;
	}

	// Only the SDK connection boundary is injectable; the lifecycle loop is shared.
	#[allow(clippy::too_many_arguments)]
	async fn run_tunnel<H, E, C, CF>(
		log: log::Logger,
		mut connect: impl FnMut(String) -> BoxFuture<'static, Result<H, WrappedError>> + Send,
		endpoint: impl Fn(&H) -> TunnelEndpoint + Send,
		mut close: C,
		mut close_rx: mpsc::Receiver<()>,
		endpoint_tx: watch::Sender<Option<Result<TunnelEndpoint, WrappedError>>>,
		access_token_provider: impl AccessTokenProvider + 'static,
		status: StatusLock,
	) where
		H: Future<Output = Result<(), E>> + Unpin + Send,
		E: std::fmt::Display,
		C: FnMut(H) -> CF + Send,
		CF: Future<Output = Result<(), WrappedError>> + Send,
	{
		// The singleton outlives this task, including on cancellation or token failure.
		let _status_guard = TunnelStatusGuard(status.clone());
		let mut backoff = Backoff::new(Duration::from_secs(5), Duration::from_secs(120));
		let mut token_ka: Option<TokenKeepAliveTask> = None;
		let mut keepalive_finished = false;

		macro_rules! fail {
			($e: expr, $msg: expr) => {
				let recovery = if access_token_provider.authentication_required() {
					protocol::singleton::RecoveryState::AuthenticationRequired
				} else {
					protocol::singleton::RecoveryState::Retrying
				};
				fail!($e, $msg, recovery);
			};
			($e: expr, $msg: expr, $recovery: expr) => {
				let error = $e;
				let fmt = format!("{}: {}", $msg, error);
				warning!(log, &fmt);
				status.fail_with_recovery(fmt, $recovery);
				endpoint_tx.send(Some(Err(error))).ok();
				tokio::select! {
					_ = close_rx.recv() => return,
					_ = backoff.delay() => {},
				}
			};
		}

		loop {
			if close_rx.is_closed() {
				break;
			}
			if token_ka.as_ref().is_some_and(|task| task.0.is_finished()) {
				let mut task = token_ka.take().unwrap();
				match keepalive_result((&mut task.0).await) {
					Ok(()) => keepalive_finished = true,
					Err(error) => {
						let (error, recovery) = keepalive_failure(
							error,
							access_token_provider.authentication_required(),
						);
						fail!(error, "Credential keep-alive failed, will retry", recovery);
						continue;
					}
				}
			}
			debug!(log, "Starting tunnel to server...");
			status.recovering(protocol::singleton::RecoveryState::Connecting);

			let token_result = tokio::select! {
				biased;
				_ = close_rx.recv() => break,
				result = tokio::time::timeout(TOKEN_REFRESH_TIMEOUT, access_token_provider.refresh_token()) => {
					result.unwrap_or_else(|e| Err(wrap(e, "timed out acquiring tunnel token")))
				},
			};
			let access_token = match token_result {
				Ok(t) => t,
				Err(e) => {
					fail!(e, "Error refreshing access token, will retry");
					continue;
				}
			};

			// we don't bother making a client that can refresh the token, since
			// the tunnel won't be able to host as soon as the access token expires.
			let handle_res = tokio::select! {
				biased;
				_ = close_rx.recv() => break,
				result = tokio::time::timeout(RELAY_CONNECT_TIMEOUT, connect(access_token)) => {
					result.unwrap_or_else(|e| Err(wrap(e, "timed out connecting to relay")))
				},
			};

			let mut handle = match handle_res {
				Ok(handle) => handle,
				Err(e) => {
					fail!(e, "Error connecting to relay, will retry");
					continue;
				}
			};

			backoff.reset();
			status.succeed();
			endpoint_tx.send(Some(Ok(endpoint(&handle)))).ok();

			if token_ka.is_none() && !keepalive_finished {
				token_ka = Some(TokenKeepAliveTask(tokio::spawn(
					access_token_provider.keep_alive(),
				)));
			}
			loop {
				tokio::select! {
				biased;
				_ = close_rx.recv() => {
					status.fail_with_recovery("Tunnel relay task stopped".to_string(), protocol::singleton::RecoveryState::Closing);
					Self::close_relay(&log, &status, close(handle)).await;
					return;
				},
				// error is mapped like this prevent it being used across an await,
				// which Rust dislikes since there's a non-sendable dyn Error in there
				res = (&mut handle).map_err(|e| wrap(e, "error from tunnel connection")) => {
					if let Err(e) = res {
						fail!(e, "Tunnel exited unexpectedly, reconnecting");
					} else {
						status.fail("Tunnel exited unexpectedly but gracefully, reconnecting".to_string());
						warning!(log, "Tunnel exited unexpectedly but gracefully, reconnecting");
						tokio::select! {
							_ = close_rx.recv() => return,
							_ = backoff.delay() => {},
						}
					}
					break;
				},
				result = async { (&mut token_ka.as_mut().unwrap().0).await }, if token_ka.is_some() => {
					drop(token_ka.take());
					if let Err(e) = keepalive_result(result) {
						let (error, recovery) = keepalive_failure(e, access_token_provider.authentication_required());
						warning!(log, "{}", error);
						status.fail_with_recovery(error.to_string(), recovery);
						endpoint_tx.send(Some(Err(error))).ok();
						// Dropping the pinned SDK's RelayHandle detaches its worker.
						// Confirm closure before establishing a replacement connection.
						if !Self::close_relay(&log, &status, close(handle)).await {
							return;
						}
						tokio::select! {
							_ = close_rx.recv() => return,
							_ = backoff.delay() => {},
						}
						break;
					} else {
						keepalive_finished = true;
					}
				},
				}
			}
		}
	}

	async fn close_relay(
		log: &log::Logger,
		status: &StatusLock,
		close: impl Future<Output = Result<(), WrappedError>>,
	) -> bool {
		let previous_recovery = status.read().recovery;
		tokio::pin!(close);
		let result = tokio::select! {
			result = &mut close => result,
			_ = tokio::time::sleep(RELAY_CLEANUP_TIMEOUT) => {
				let message = "Relay cleanup is blocked; waiting before reconnecting";
				warning!(log, "{}", message);
				status.fail_with_recovery(message.to_string(), protocol::singleton::RecoveryState::CleanupBlocked);
				close.await
			},
		};
		match result {
			Ok(()) => {
				if status.read().recovery
					== Some(protocol::singleton::RecoveryState::CleanupBlocked)
				{
					status.recovering(
						previous_recovery.unwrap_or(protocol::singleton::RecoveryState::Closing),
					);
				}
				true
			}
			Err(error) => {
				error!(
					log,
					"Relay cleanup failed; replacement is unsafe: {}", error
				);
				status.fail_with_recovery(
					"Relay cleanup failed; replacement is unsafe".to_string(),
					protocol::singleton::RecoveryState::Failed,
				);
				false
			}
		}
	}
}

#[cfg(test)]
#[path = "stale_health_relay_tests.rs"]
mod stale_health_regression;

#[cfg(test)]
#[path = "native_relay_recovery_tests.rs"]
mod native_recovery;

#[cfg(test)]
#[path = "native_recovery_cli_tests.rs"]
mod native_recovery_cli_tests;

struct Backoff {
	failures: u32,
	base_duration: Duration,
	max_duration: Duration,
}

impl Backoff {
	pub fn new(base_duration: Duration, max_duration: Duration) -> Self {
		Self {
			failures: 0,
			base_duration,
			max_duration,
		}
	}

	pub async fn delay(&mut self) {
		tokio::time::sleep(self.next()).await
	}

	pub fn next(&mut self) -> Duration {
		self.failures += 1;
		let duration = self
			.base_duration
			.checked_mul(self.failures)
			.unwrap_or(self.max_duration);
		std::cmp::min(duration, self.max_duration)
	}

	pub fn reset(&mut self) {
		self.failures = 0;
	}
}

/// Cleans up the hostname so it can be used as a tunnel name.
/// See TUNNEL_NAME_PATTERN in the tunnels SDK for the rules we try to use.
fn clean_hostname_for_tunnel(hostname: &str) -> String {
	let mut out = String::new();
	for char in hostname.chars().take(60) {
		match char {
			'-' | '_' | ' ' => {
				out.push('-');
			}
			'0'..='9' | 'a'..='z' | 'A'..='Z' => {
				out.push(char);
			}
			_ => {}
		}
	}

	let trimmed = out.trim_matches('-');
	if trimmed.len() < 2 {
		"remote-machine".to_string() // placeholder if the result was empty
	} else {
		trimmed.to_owned()
	}
}

fn vec_eq_as_set(a: &[String], b: &[String]) -> bool {
	if a.len() != b.len() {
		return false;
	}

	for item in a {
		if !b.contains(item) {
			return false;
		}
	}

	true
}

// This is only relevant for Node-owned tunnels created before
// https://github.com/microsoft/vscode/pull/329066 was merged. The pinned dev-tunnels
// revision does not expose the inner HttpError as Error::source(), so match its detail
// in the formatted error until the SDK provides a structured error code.
fn is_tunnel_port_protocol_conflict(error: &impl std::fmt::Display) -> bool {
	error
		.to_string()
		.contains(TUNNEL_PORT_PROTOCOL_CONFLICT_DETAIL)
}

fn privacy_to_tunnel_acl(privacy: PortPrivacy) -> TunnelAccessControl {
	TunnelAccessControl {
		entries: vec![match privacy {
			PortPrivacy::Public => tunnels::contracts::TunnelAccessControlEntry {
				kind: tunnels::contracts::TunnelAccessControlEntryType::Anonymous,
				provider: None,
				is_inherited: false,
				is_deny: false,
				is_inverse: false,
				organization: None,
				expiration: None,
				subjects: vec![],
				scopes: vec![TUNNEL_ACCESS_SCOPES_CONNECT.to_string()],
			},
			// Ensure private ports are actually private and do not inherit any
			// default visibility that may be set on the tunnel:
			PortPrivacy::Private => tunnels::contracts::TunnelAccessControlEntry {
				kind: tunnels::contracts::TunnelAccessControlEntryType::Anonymous,
				provider: None,
				is_inherited: false,
				is_deny: true,
				is_inverse: false,
				organization: None,
				expiration: None,
				subjects: vec![],
				scopes: vec![TUNNEL_ACCESS_SCOPES_CONNECT.to_string()],
			},
		}],
	}
}

fn tunnel_has_host_connection(tunnel: &Tunnel) -> bool {
	tunnel
		.status
		.as_ref()
		.and_then(|s| s.host_connection_count.as_ref().map(|c| c.get_count() > 0))
		.unwrap_or_default()
}

#[cfg(test)]
mod test {
	use super::*;

	#[tokio::test]
	async fn cancelled_relay_task_does_not_leave_singleton_connected() {
		let status = StatusLock::default();
		let task_status = status.clone();
		let (started_tx, started_rx) = tokio::sync::oneshot::channel();
		let task = tokio::spawn(async move {
			let _guard = TunnelStatusGuard(task_status.clone());
			task_status.succeed();
			started_tx.send(()).unwrap();
			futures::future::pending::<()>().await;
		});
		started_rx.await.unwrap();
		task.abort();
		assert!(task.await.unwrap_err().is_cancelled());

		let state = status.read();
		assert!(matches!(
			state.tunnel,
			protocol::singleton::TunnelState::Disconnected
		));
		assert!(state.last_disconnected_at.is_some());
		assert_eq!(
			state.last_fail_reason.as_deref(),
			Some("Tunnel relay task stopped")
		);
	}

	#[tokio::test]
	async fn relay_task_exit_preserves_specific_failure() {
		let status = StatusLock::default();
		let task_status = status.clone();
		tokio::spawn(async move {
			let _guard = TunnelStatusGuard(task_status.clone());
			task_status.succeed();
			task_status.fail("access token is no longer valid".to_string());
		})
		.await
		.unwrap();

		let state = status.read();
		assert!(matches!(
			state.tunnel,
			protocol::singleton::TunnelState::Disconnected
		));
		assert_eq!(
			state.last_fail_reason.as_deref(),
			Some("access token is no longer valid")
		);
	}

	#[test]
	fn test_tunnel_correlation_preserves_telemetry_session_id() {
		let session_id = "7c86e247-3438-4f26-959d-061b3299f4de1791567000000";
		assert_eq!(
			tunnel_correlation_id(
				&log::Logger::test(),
				"VSCODE_TUNNEL_SESSION_ID",
				Ok(session_id.to_string()),
				uuid::Uuid::new_v4(),
			),
			HeaderValue::from_static(session_id),
		);
	}

	#[test]
	fn test_tunnel_correlation_rejects_invalid_header_values() {
		let fallback = uuid::Uuid::new_v4();
		for value in ["", "session\r\ninjected-header: value"] {
			assert_eq!(
				tunnel_correlation_id(
					&log::Logger::test(),
					"VSCODE_TUNNEL_SESSION_ID",
					Ok(value.to_string()),
					fallback,
				),
				HeaderValue::from_str(&fallback.to_string()).unwrap(),
			);
		}
	}

	#[test]
	fn test_tunnel_request_correlation() {
		let client: TunnelManagementClient = tunnel_management_client(&log::Logger::test()).into();
		let first = client.request_headers();
		let second = client.request_headers();
		assert_eq!(
			first
				.iter()
				.map(|(name, _)| name.as_str())
				.collect::<Vec<_>>(),
			vec![
				"x-tunnels-vscode-session-id",
				"x-tunnels-vscode-client-operation-id",
				"x-tunnels-vscode-client-request-id",
			]
		);
		for (_, value) in &first {
			assert!(uuid::Uuid::parse_str(value.to_str().unwrap()).is_ok());
		}
		assert_eq!(&first[..2], &second[..2]);
		assert_ne!(first[2].1, second[2].1);
	}

	#[test]
	fn test_clean_hostname_for_tunnel() {
		assert_eq!(
			clean_hostname_for_tunnel("hello123"),
			"hello123".to_string()
		);
		assert_eq!(
			clean_hostname_for_tunnel("-cool-name-"),
			"cool-name".to_string()
		);
		assert_eq!(
			clean_hostname_for_tunnel("cool!name with_chars"),
			"coolname-with-chars".to_string()
		);
		assert_eq!(clean_hostname_for_tunnel("z"), "remote-machine".to_string());
	}

	#[test]
	fn test_is_tunnel_port_protocol_conflict() {
		assert!(is_tunnel_port_protocol_conflict(&format!(
			"failed to add port to tunnel: response error: HTTP status 400: \
			 {{\"detail\":\"{TUNNEL_PORT_PROTOCOL_CONFLICT_DETAIL}\"}}"
		)));
		assert!(!is_tunnel_port_protocol_conflict(
			&"response error: Another validation error."
		));
	}
}
