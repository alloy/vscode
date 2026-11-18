/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::*;
use crate::{
	singleton::{acquire_singleton, SingletonConnection},
	tunnels::{machine_status, singleton_server},
};
use std::{
	path::{Path, PathBuf},
	pin::Pin,
	process::Stdio,
	sync::atomic::{AtomicBool, Ordering},
	task::{Context, Poll},
};
use tokio::{
	io::{AsyncBufReadExt, BufReader},
	process::{Child, Command},
	sync::oneshot,
	task::JoinHandle,
};

const INITIAL: &str = "synthetic-demo-credential-v1";
const REPLACEMENT: &str = "synthetic-demo-credential-v2";

struct DemoProvider {
	auth: auth::Auth,
	credential_path: PathBuf,
	credential_rejected: Arc<AtomicBool>,
	reject_keepalive: Arc<AtomicBool>,
}

impl AccessTokenProvider for DemoProvider {
	async fn refresh_token(&self) -> Result<String, WrappedError> {
		assert_file_credential(&self.credential_path);
		assert_safe_credential(&self.auth);
		let credential = self
			.auth
			.get_credential()
			.await
			.map_err(|error| wrap(error, "production Auth could not load demo credential"))?;
		let token = credential.access_token();
		if token == INITIAL && self.credential_rejected.load(Ordering::SeqCst) {
			Err(wrap("synthetic credential rejected", "demo SDK boundary"))
		} else {
			Ok(token.to_string())
		}
	}

	fn keep_alive(&self) -> BoxFuture<'static, Result<(), AnyError>> {
		let rejected = self.reject_keepalive.clone();
		async move {
			loop {
				if rejected.swap(false, Ordering::SeqCst) {
					return Err(DevTunnelError("synthetic keepalive rejection".to_string()).into());
				}
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		}
		.boxed()
	}
}

struct DemoRelay(oneshot::Receiver<Result<(), WrappedError>>);

// Keep identical fixture instrumentation across the baseline's string close
// callback and the hardened lifecycle's typed close result.
struct DemoCloseSucceeded;

impl From<DemoCloseSucceeded> for String {
	fn from(_: DemoCloseSucceeded) -> Self {
		"synthetic SDK close completed".to_string()
	}
}

impl From<DemoCloseSucceeded> for Result<(), WrappedError> {
	fn from(_: DemoCloseSucceeded) -> Self {
		Ok(())
	}
}

impl Future for DemoRelay {
	type Output = Result<(), WrappedError>;

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		Pin::new(&mut self.0)
			.poll(cx)
			.map(|result| result.expect("demo relay controller dropped"))
	}
}

struct Worker(JoinHandle<()>);

impl Drop for Worker {
	fn drop(&mut self) {
		self.0.abort();
	}
}

struct AttachedCli {
	child: Child,
	lines: Arc<Mutex<Vec<String>>>,
	readers: Vec<JoinHandle<()>>,
}

impl AttachedCli {
	fn start(binary: &Path, profile: &Path) -> Self {
		let mut command = cli_command(binary, profile);
		command.args([
			"--verbose",
			"tunnel",
			"--machine-status",
			"--accept-server-license-terms",
		]);
		println!("[source=normal-cli foreground command={command:?}]");
		let mut child = command.spawn().unwrap();
		let lines = Arc::new(Mutex::new(Vec::new()));
		let mut readers = Vec::new();
		for (stream, label) in [
			(
				Box::pin(child.stdout.take().unwrap()) as Pin<Box<dyn tokio::io::AsyncRead + Send>>,
				"stdout",
			),
			(Box::pin(child.stderr.take().unwrap()), "stderr"),
		] {
			let captured = lines.clone();
			readers.push(tokio::spawn(async move {
				let mut reader = BufReader::new(stream).lines();
				while let Some(line) = reader.next_line().await.unwrap() {
					println!("[source=normal-cli foreground {label}] {line}");
					captured.lock().unwrap().push(line);
				}
			}));
		}
		Self {
			child,
			lines,
			readers,
		}
	}

	fn counts(&self) -> (usize, usize) {
		let lines = self.lines.lock().unwrap();
		(
			lines
				.iter()
				.filter(|l| l.contains("is listening for incoming connections"))
				.count(),
			lines
				.iter()
				.filter(|l| {
					l.starts_with("__VSCODE_CLI_STATUS__") && l.contains("\"type\":\"connected\"")
				})
				.count(),
		)
	}

	async fn readiness(&self, minimum: usize) -> bool {
		tokio::time::timeout(Duration::from_secs(3), async {
			loop {
				let (human, machine) = self.counts();
				if human >= minimum && machine >= minimum {
					break;
				}
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		})
		.await
		.is_ok()
	}

	async fn stop(&mut self) {
		self.child.kill().await.unwrap();
		for reader in self.readers.drain(..) {
			reader.await.unwrap();
		}
	}
}

impl Drop for AttachedCli {
	fn drop(&mut self) {
		let _ = self.child.start_kill();
		for reader in &self.readers {
			reader.abort();
		}
	}
}

fn cli_command(binary: &Path, profile: &Path) -> Command {
	let mut command = Command::new(binary);
	command
		.arg("--cli-data-dir")
		.arg(profile)
		.env("VSCODE_CLI_USE_FILE_KEYCHAIN", "1")
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true);
	command
}

fn assert_file_credential(path: &Path) {
	assert!(path.is_absolute() && path.file_name().unwrap() == "token.json");
	assert!(path.is_file(), "guard: isolated file credential must exist");
	let contents = std::fs::read_to_string(path).unwrap();
	let sealed: Option<String> = serde_json::from_str(&contents).unwrap();
	assert!(
		sealed.is_some_and(|value| !value.is_empty()),
		"guard: isolated credential must not be missing or empty"
	);
}

fn assert_safe_credential(auth: &auth::Auth) -> String {
	let credential = auth
		.get_current_credential()
		.unwrap()
		.expect("guard: valid stored credential required before get_credential");
	assert!(matches!(credential.provider, auth::AuthProvider::Microsoft));
	assert!(matches!(credential.access_token(), INITIAL | REPLACEMENT));
	let token = credential.access_token().to_string();
	let encoded = serde_json::to_value(credential).unwrap();
	assert!(
		encoded["r"].is_null() && encoded["e"].is_null(),
		"guard: synthetic Microsoft credentials must have no refresh token or expiry"
	);
	token
}

async fn login(binary: &Path, profile: &Path, token: &str, phase: &str) {
	assert!(matches!(token, INITIAL | REPLACEMENT));
	let mut command = cli_command(binary, profile);
	command.args([
		"tunnel",
		"user",
		"login",
		"--provider",
		"microsoft",
		"--access-token",
		token,
	]);
	println!("[source=normal-cli login phase={phase} command={command:?}]");
	let output = tokio::time::timeout(Duration::from_secs(15), command.output())
		.await
		.unwrap()
		.unwrap();
	println!(
		"[source=normal-cli login phase={phase} exit={}]",
		output.status
	);
	println!(
		"[source=normal-cli login phase={phase} stdout] {}",
		String::from_utf8_lossy(&output.stdout).trim()
	);
	if !output.stderr.is_empty() {
		println!(
			"[source=normal-cli login phase={phase} stderr] {}",
			String::from_utf8_lossy(&output.stderr).trim()
		);
	}
	assert!(output.status.success(), "normal CLI login failed");
	assert_file_credential(&profile.join("token.json"));
	let paths = LauncherPaths::new(Some(profile.to_string_lossy().into_owned())).unwrap();
	let verification = auth::Auth::new(&paths, log::Logger::test());
	assert_eq!(assert_safe_credential(&verification), token);
	println!(
		"[source=production-auth fresh-reader phase={phase} stored_credential_generation={}]",
		if token == REPLACEMENT { 2 } else { 1 }
	);
}

async fn query(binary: &Path, profile: &Path, phase: &str) -> serde_json::Value {
	let mut command = cli_command(binary, profile);
	command.args(["tunnel", "status"]);
	println!("[source=normal-cli status phase={phase} command={command:?}]");
	let output = tokio::time::timeout(Duration::from_secs(15), command.output())
		.await
		.unwrap()
		.unwrap();
	let stdout = String::from_utf8(output.stdout).unwrap();
	let stderr = String::from_utf8(output.stderr).unwrap();
	println!(
		"[source=normal-cli status phase={phase} stdout] {}",
		stdout.trim()
	);
	if !stderr.is_empty() {
		println!(
			"[source=normal-cli status phase={phase} stderr] {}",
			stderr.trim()
		);
	}
	assert!(output.status.success(), "status command failed");
	stdout
		.lines()
		.find_map(|line| serde_json::from_str(line).ok())
		.expect("normal CLI must emit JSON")
}

fn singleton_identity(path: &Path) -> (String, u32) {
	use std::io::{Seek, SeekFrom};
	let mut file = std::fs::File::open(path).unwrap();
	file.seek(SeekFrom::Start(
		crate::util::file_lock::PREFIX_LOCKED_BYTES as u64,
	))
	.unwrap();
	rmp_serde::from_read(file).unwrap()
}

async fn status_is(status: &StatusLock, connected: bool) {
	tokio::time::timeout(Duration::from_secs(20), async {
		loop {
			if matches!(
				status.read().tunnel,
				protocol::singleton::TunnelState::Connected
			) == connected
			{
				break;
			}
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await
	.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit VSCODE_CLI_TEST_BINARY; see TUNNEL_NATIVE_RECOVERY.md"]
async fn native_recovery_cli_demo() {
	let binary = PathBuf::from(
		std::env::var_os("VSCODE_CLI_TEST_BINARY")
			.expect("supply the absolute path to the normal CLI executable"),
	);
	assert!(binary.is_absolute() && binary.is_file());
	let expected_recovery = match std::env::var("VSCODE_CLI_TEST_EXPECT_RECOVERY").as_deref() {
		Ok("0") => false,
		Ok("1") => true,
		_ => panic!("set VSCODE_CLI_TEST_EXPECT_RECOVERY=0 (baseline) or 1 (fixed)"),
	};
	let _machine_lock = machine_status::STATUS_TEST_LOCK.lock().await;
	let root = std::env::current_dir()
		.unwrap()
		.join("target")
		.join("native-recovery-demo");
	std::fs::create_dir_all(&root).unwrap();
	let directory = tempfile::Builder::new()
		.prefix("profile-")
		.tempdir_in(root)
		.unwrap();
	let profile = directory.path();
	let paths = LauncherPaths::new(Some(profile.to_string_lossy().into_owned())).unwrap();
	let singleton = match acquire_singleton(&paths.tunnel_lockfile()).await.unwrap() {
		SingletonConnection::Singleton(server) => server,
		_ => panic!("demo must exclusively own its isolated profile"),
	};
	let identity = singleton_identity(&paths.tunnel_lockfile());
	assert_eq!(identity.1, std::process::id());
	println!("[source=test-fixture singleton_pid={} binary={} profile={} expected_recovery={expected_recovery}]", std::process::id(), binary.display(), profile.display());
	let credential_path = profile.join("token.json");
	assert!(!credential_path.exists());
	login(&binary, profile, INITIAL, "initial-credential").await;
	assert_file_credential(&credential_path);
	let auth = auth::Auth::new(&paths, log::Logger::test());
	assert_safe_credential(&auth);
	let credential_rejected = Arc::new(AtomicBool::new(false));
	let reject_keepalive = Arc::new(AtomicBool::new(false));
	let broadcast = singleton_server::BroadcastLogSink::new();
	let status = StatusLock::default();
	let mut rpc = singleton_server::native_recovery_rpc_fixture::serve(
		singleton,
		status.clone(),
		broadcast.clone(),
	);
	let (close, close_rx) = mpsc::channel(1);
	let (endpoint_tx, _endpoint_rx) = watch::channel(None);
	let (relay_tx, mut relays) = mpsc::unbounded_channel();
	let mut worker = Worker(tokio::spawn(ActiveTunnelManager::run_tunnel(
		log::Logger::test().with_sink(broadcast),
		move |token| {
			let (end, rx) = oneshot::channel();
			println!(
				"[source=synthetic-sdk relay-connect credential_generation={}]",
				if token == REPLACEMENT { 2 } else { 1 }
			);
			relay_tx.send(end).unwrap();
			futures::future::ready(Ok(DemoRelay(rx))).boxed()
		},
		|_: &DemoRelay| {
			serde_json::from_value(serde_json::json!({
				"connectionMode": "TunnelRelay", "hostId": "synthetic-sdk-host"
			}))
			.unwrap()
		},
		|_: DemoRelay| async { DemoCloseSucceeded.into() },
		close_rx,
		endpoint_tx,
		DemoProvider {
			auth,
			credential_path,
			credential_rejected: credential_rejected.clone(),
			reject_keepalive: reject_keepalive.clone(),
		},
		status.clone(),
	)));
	let first = tokio::time::timeout(Duration::from_secs(3), relays.recv())
		.await
		.unwrap()
		.unwrap();
	status_is(&status, true).await;
	let initial = query(&binary, profile, "initial-connected").await;
	assert_eq!(initial["tunnel"]["tunnel"], "Connected");
	let mut attached = AttachedCli::start(&binary, profile);
	assert!(
		attached.readiness(1).await,
		"initial attachment readiness missing"
	);

	first
		.send(Err(wrap(
			"synthetic transient relay disconnect",
			"demo SDK boundary",
		)))
		.unwrap();
	status_is(&status, false).await;
	let transient = query(&binary, profile, "transient-disconnected").await;
	assert_eq!(transient["tunnel"]["tunnel"], "Disconnected");
	let second = tokio::time::timeout(Duration::from_secs(20), relays.recv())
		.await
		.unwrap()
		.unwrap();
	status_is(&status, true).await;
	let reconnected = query(&binary, profile, "transient-reconnected").await;
	assert_eq!(reconnected["tunnel"]["tunnel"], "Connected");
	assert!(
		attached.readiness(2).await,
		"fresh transient reconnect readiness missing"
	);

	credential_rejected.store(true, Ordering::SeqCst);
	reject_keepalive.store(true, Ordering::SeqCst);
	status_is(&status, false).await;
	let failed = query(&binary, profile, "credential-rejected").await;
	assert_eq!(failed["tunnel"]["tunnel"], "Disconnected");
	let before = attached.counts();
	tokio::time::sleep(Duration::from_millis(250)).await;
	assert_eq!(
		before,
		attached.counts(),
		"rejection emitted false readiness"
	);
	login(&binary, profile, REPLACEMENT, "replacement-credential").await;
	let third = tokio::time::timeout(Duration::from_secs(20), relays.recv()).await;
	let recovered = matches!(&third, Ok(Some(_)));
	if recovered {
		status_is(&status, true).await;
	}
	let result = query(
		&binary,
		profile,
		"after-separate-process-credential-replacement",
	)
	.await;
	assert_eq!(identity, singleton_identity(&paths.tunnel_lockfile()));
	println!(
		"[source=observation singleton_pid={} worker_finished={} recovered={recovered}]",
		std::process::id(),
		worker.0.is_finished()
	);
	assert_eq!(
		recovered, expected_recovery,
		"observed recovery differs from selected baseline/fixed expectation"
	);
	assert_eq!(
		result["tunnel"]["tunnel"],
		if recovered {
			"Connected"
		} else {
			"Disconnected"
		}
	);
	if recovered {
		assert!(
			attached.readiness(3).await,
			"replacement credential reconnect readiness missing"
		);
		assert!(
			!worker.0.is_finished(),
			"singleton worker must remain alive"
		);
	} else {
		assert_eq!(
			before,
			attached.counts(),
			"baseline must not invent fresh readiness"
		);
		assert!(
			worker.0.is_finished(),
			"baseline failure should terminate its worker"
		);
	}
	let _ = close.send(()).await;
	tokio::time::timeout(Duration::from_secs(3), &mut worker.0)
		.await
		.unwrap()
		.unwrap();
	attached.stop().await;
	rpc.stop().await;
	drop(second);
	drop(third);
	drop(rpc);
	directory.close().unwrap();
}
