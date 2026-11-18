/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::*;
use crate::{
	singleton::{acquire_singleton, connect_as_client, SingletonConnection},
	tunnels::{
		machine_status::MachineStatus,
		protocol::singleton::TunnelState,
		singleton_client::{do_single_rpc_call, start_singleton_client, SingletonClientArgs},
	},
	util::sync::{new_barrier, BarrierOpener},
};
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<String>>>);

impl log::LogSink for CapturedLog {
	fn write_log(&self, _: log::Level, _: &str, message: &str) {
		self.0.lock().unwrap().push(message.to_string());
	}

	fn write_result(&self, message: &str) {
		self.0.lock().unwrap().push(message.to_string());
	}
}

struct Fixture {
	client: Option<JoinHandle<bool>>,
	server: RpcServer,
	lock: PathBuf,
	broadcast: BroadcastLogSink,
	logs: CapturedLog,
	machine: Arc<Mutex<Vec<MachineStatus>>>,
	stdout: machine_status::RegressionStdoutCapture,
	_server_shutdown: BarrierOpener<ShutdownSignal>,
	client_shutdown: Option<BarrierOpener<ShutdownSignal>>,
	_directory: tempfile::TempDir,
	_machine_lock: tokio::sync::MutexGuard<'static, ()>,
}

#[tokio::test]
async fn startup_authentication_failure_is_visible_before_tunnel_registration() {
	let fixture = Fixture::new(false, false).await;
	*fixture.server.current_status.lock().unwrap() = None;
	fixture.server.report_startup_failure(
		"Authentication required; complete explicit login".to_string(),
		true,
	);
	let status = fixture.query_status().await;
	assert!(status.name.is_none());
	assert!(status.tunnel_id.is_none());
	assert!(matches!(status.status.tunnel, TunnelState::Disconnected));
	assert_eq!(
		status.status.recovery,
		Some(protocol::singleton::RecoveryState::AuthenticationRequired)
	);
	assert!(status
		.status
		.last_fail_reason
		.unwrap()
		.contains("explicit login"));
}

impl Drop for Fixture {
	fn drop(&mut self) {
		if let Some(client) = &self.client {
			client.abort();
		}
		self.server.fut.abort();
		machine_status::install_sink(|_| {});
	}
}

impl Fixture {
	async fn new(connected: bool, historical_readiness: bool) -> Self {
		let status = StatusLock::default();
		if connected {
			status.connect_for_regression();
		}
		Self::with_status(status, historical_readiness).await
	}

	async fn with_status(status: StatusLock, historical_readiness: bool) -> Self {
		let machine_lock = machine_status::STATUS_TEST_LOCK.lock().await;
		let directory = tempfile::tempdir().unwrap();
		let lock = directory.path().join("offline-regression.lock");
		let singleton = match acquire_singleton(&lock).await.unwrap() {
			SingletonConnection::Singleton(server) => server,
			_ => panic!("fixture must own its private singleton"),
		};
		let broadcast = BroadcastLogSink::new();
		if historical_readiness {
			print_listening(
				&log::Logger::test().with_sink(broadcast.clone()),
				"offline-regression-host",
				true,
			);
		}
		let (shutdown, shutdown_opener) = new_barrier();
		let mut server = make_singleton_server(
			broadcast.clone(),
			log::Logger::test().with_sink(broadcast.clone()),
			singleton,
			shutdown,
		);
		server.set_current_status(StatusInfo {
			name: "offline-regression-host".to_string(),
			tunnel_id: "offline-regression-id".to_string(),
			lock: status.clone(),
		});
		let logs = CapturedLog::default();
		let machine = Arc::new(Mutex::new(Vec::new()));
		let events = machine.clone();
		machine_status::install_sink(move |event| events.lock().unwrap().push(event.clone()));
		let stdout = machine_status::RegressionStdoutCapture::new();
		Self {
			client: None,
			server,
			lock,
			broadcast,
			logs,
			machine,
			stdout,
			_server_shutdown: shutdown_opener,
			client_shutdown: None,
			_directory: directory,
			_machine_lock: machine_lock,
		}
	}

	async fn attach(&mut self) {
		let stream = connect_as_client(&self.lock).await.unwrap();
		let (shutdown, shutdown_opener) = new_barrier();
		self.client_shutdown = Some(shutdown_opener);
		self.client = Some(tokio::spawn(start_singleton_client(SingletonClientArgs {
			log: log::Logger::test().with_sink(self.logs.clone()),
			stream,
			shutdown,
			machine_status_enabled: true,
		})));
		// A successful status RPC behind attachment is a real pipe/server barrier.
		self.query_status().await;
		tokio::time::timeout(Duration::from_secs(2), async {
			loop {
				if self
					.logs
					.0
					.lock()
					.unwrap()
					.iter()
					.any(|line| line.contains("Connected to an existing tunnel process"))
				{
					break;
				}
				tokio::time::sleep(Duration::from_millis(5)).await;
			}
		})
		.await
		.unwrap();
		tokio::time::sleep(Duration::from_millis(100)).await;
	}

	async fn query_status(&self) -> protocol::singleton::StatusWithTunnelName {
		tokio::time::timeout(
			Duration::from_secs(2),
			do_single_rpc_call(
				&self.lock,
				log::Logger::test(),
				protocol::singleton::METHOD_STATUS,
				protocol::EmptyObject {},
			),
		)
		.await
		.unwrap()
		.unwrap()
	}

	fn listening_count(&self) -> usize {
		self.logs
			.0
			.lock()
			.unwrap()
			.iter()
			.filter(|line| line.contains("is listening for incoming connections"))
			.count()
	}

	async fn wait_for_readiness(&self, count: usize) {
		tokio::time::timeout(Duration::from_secs(2), async {
			loop {
				if self.listening_count() >= count && self.stdout.events().len() >= count {
					break;
				}
				tokio::time::sleep(Duration::from_millis(5)).await;
			}
		})
		.await
		.unwrap();
	}
}

#[tokio::test]
async fn restart_rpc_disconnects_before_shutdown_observers_run() {
	let fixture = Fixture::new(true, false).await;
	let mut restart = fixture.server.shutdown_broadcast.subscribe();
	let _: () = do_single_rpc_call(
		&fixture.lock,
		log::Logger::test(),
		protocol::singleton::METHOD_RESTART,
		protocol::EmptyObject {},
	)
	.await
	.unwrap();
	assert!(matches!(
		restart.try_recv().unwrap(),
		ShutdownSignal::RpcRestartRequested
	));
	let status = fixture.query_status().await;
	assert!(
		matches!(status.status.tunnel, TunnelState::Disconnected),
		"restart RPC acknowledged while singleton still reports Connected"
	);
	assert_eq!(
		status.status.last_fail_reason.as_deref(),
		Some("Tunnel restart requested")
	);
	assert!(status.status.last_disconnected_at.is_some());
}

#[tokio::test]
async fn disconnected_attachment_synthesizes_neither_readiness_contract() {
	let mut fixture = Fixture::new(false, false).await;
	fixture.attach().await;
	assert_eq!(
		(
			fixture.listening_count(),
			fixture.machine.lock().unwrap().len(),
			fixture.stdout.events().len(),
		),
		(0, 0, 0),
		"disconnected attachment must not synthesize human, relay, or stdout readiness"
	);
}

#[tokio::test]
async fn connected_attachment_preserves_human_and_machine_readiness() {
	let mut fixture = Fixture::new(true, false).await;
	fixture.attach().await;
	assert_eq!(fixture.listening_count(), 1);
	let events = fixture.machine.lock().unwrap();
	assert!(matches!(
		events.as_slice(),
		[MachineStatus::Connected {
			tunnel_name,
			tunnel_id: Some(id),
			is_attached: true,
			..
		}] if tunnel_name == "offline-regression-host" && id == "offline-regression-id"
	));
	assert_eq!(*events, fixture.stdout.events());
	let encoded = serde_json::to_value(&events[0]).unwrap();
	assert_eq!(encoded["type"], "connected");
	assert_eq!(encoded["isAttached"], true);
}

#[tokio::test]
async fn historical_human_log_replay_is_not_a_current_machine_event() {
	let mut fixture = Fixture::new(false, true).await;
	fixture.attach().await;
	assert_eq!(
		(
			fixture.listening_count(),
			fixture.machine.lock().unwrap().len(),
			fixture.stdout.events().len(),
		),
		(1, 0, 0),
		"only historical human readiness should be replayed"
	);
	assert!(matches!(
		fixture.query_status().await.status.tunnel,
		TunnelState::Disconnected
	));
}

#[tokio::test]
async fn subsequent_real_readiness_notifications_reach_attached_consumers() {
	let mut fixture = Fixture::new(false, false).await;
	fixture.attach().await;
	fixture.machine.lock().unwrap().clear();
	fixture.stdout.clear();
	fixture.logs.0.lock().unwrap().clear();
	for _ in 0..2 {
		print_listening(
			&log::Logger::test().with_sink(fixture.broadcast.clone()),
			"offline-regression-host",
			true,
		);
		let _ = fixture
			.broadcast
			.get_brocaster()
			.send(RpcCaller::serialize_notify(
				&JsonRpcSerializer {},
				protocol::singleton::METHOD_MACHINE_STATUS,
				MachineStatus::Connected {
					tunnel_name: "offline-regression-host".to_string(),
					tunnel_id: Some("offline-regression-id".to_string()),
					is_attached: false,
					link: None,
					domain: None,
				},
			));
	}
	tokio::time::timeout(Duration::from_secs(2), async {
		loop {
			if fixture.stdout.events().len() == 2 && fixture.listening_count() == 2 {
				break;
			}
			tokio::time::sleep(Duration::from_millis(5)).await;
		}
	})
	.await
	.unwrap();
	assert_eq!(fixture.machine.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn reconnect_observer_reports_each_connection_without_disconnect_readiness() {
	let status = StatusLock::default();
	let mut fixture = Fixture::with_status(status.clone(), false).await;
	fixture.attach().await;

	for count in 1..=2 {
		status.connect_for_regression();
		fixture.wait_for_readiness(count).await;
		status.fail("synthetic disconnect".to_string());
	}
	tokio::time::sleep(Duration::from_millis(100)).await;

	assert_eq!(
		(fixture.listening_count(), fixture.stdout.events().len()),
		(2, 2)
	);
	assert!(fixture.stdout.events().iter().all(|event| matches!(
		event,
		MachineStatus::Connected {
			is_attached: false,
			..
		}
	)));
}

#[tokio::test]
async fn reconnect_observer_follows_replacement_instead_of_old_manager() {
	let old = StatusLock::default();
	let mut fixture = Fixture::with_status(old.clone(), false).await;
	fixture.attach().await;
	let replacement = StatusLock::default();
	fixture.server.set_current_status(StatusInfo {
		name: "replacement-host".to_string(),
		tunnel_id: "replacement-id".to_string(),
		lock: replacement.clone(),
	});

	old.connect_for_regression();
	replacement.connect_for_regression();
	fixture.wait_for_readiness(1).await;
	old.fail("old manager disconnected".to_string());
	old.connect_for_regression();
	tokio::time::sleep(Duration::from_millis(100)).await;

	assert_eq!(
		(fixture.listening_count(), fixture.stdout.events().len()),
		(1, 1)
	);
	assert!(matches!(
		fixture.stdout.events().as_slice(),
		[MachineStatus::Connected {
			tunnel_name,
			tunnel_id: Some(id),
			..
		}] if tunnel_name == "replacement-host" && id == "replacement-id"
	));
}

pub(in crate::tunnels) async fn assert_connection_produces_readiness(
	status: StatusLock,
	connect: impl std::future::Future<Output = ()>,
) {
	let mut fixture = Fixture::with_status(status, false).await;
	fixture.attach().await;
	fixture.machine.lock().unwrap().clear();
	fixture.stdout.clear();
	fixture.logs.0.lock().unwrap().clear();
	connect.await;
	assert!(matches!(
		fixture.query_status().await.status.tunnel,
		TunnelState::Connected
	));
	tokio::time::sleep(Duration::from_millis(100)).await;
	assert_eq!(
		(fixture.listening_count(), fixture.stdout.events().len()),
		(1, 1),
		"connection must release both human and machine readiness waiters"
	);
}
