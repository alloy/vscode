/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use std::{
	pin::Pin,
	sync::{Arc, Mutex},
};

use super::{
	code_server::CodeServerArgs,
	control_server::{AgentHostServeOptions, ServerTermination},
	dev_tunnels::{ActiveTunnel, StatusLock},
	protocol,
	shutdown_signal::{ShutdownRequest, ShutdownSignal},
};
use crate::{
	async_pipe::socket_stream_split,
	json_rpc::{new_json_rpc, start_json_rpc, JsonRpcSerializer},
	log,
	rpc::{RpcCaller, RpcDispatcher},
	singleton::SingletonServer,
	state::LauncherPaths,
	tunnels::{code_server::print_listening, machine_status},
	update_service::Platform,
	util::{
		errors::{AnyError, CodeError},
		ring_buffer::RingBuffer,
		sync::{Barrier, ConcatReceivable},
	},
};
use futures::future::Either;
use tokio::{
	pin,
	sync::{broadcast, mpsc, watch},
	task::JoinHandle,
};

#[cfg(test)]
#[path = "stale_health_rpc_tests.rs"]
pub(super) mod stale_health_regression;

pub struct SingletonServerArgs<'a> {
	pub server: &'a mut RpcServer,
	pub log: log::Logger,
	pub tunnel: ActiveTunnel,
	pub paths: &'a LauncherPaths,
	pub code_server_args: &'a CodeServerArgs,
	pub platform: Platform,
	pub user_data_dir: Option<String>,
	pub delegate_to_editor: bool,
	pub shutdown: Barrier<ShutdownSignal>,
	pub log_broadcast: &'a BroadcastLogSink,
}

struct StatusInfo {
	name: String,
	tunnel_id: String,
	lock: StatusLock,
}

#[derive(Clone)]
struct ConnectionReporter {
	name: String,
	tunnel_id: String,
	status: watch::Receiver<protocol::singleton::Status>,
}

#[derive(Clone)]
struct SingletonServerContext {
	log: log::Logger,
	shutdown_tx: broadcast::Sender<ShutdownSignal>,
	broadcast_tx: broadcast::Sender<Vec<u8>>,
	// ugly: a lock in a lock. current_status needs to be provided only
	// after we set up the tunnel, however the tunnel is created after the
	// singleton server starts to avoid a gap in singleton availability.
	// However, this should be safe, as the lock is only used for immediate
	// data reads (in the `status` method).
	current_status: Arc<Mutex<Option<StatusInfo>>>,
}

pub struct RpcServer {
	fut: JoinHandle<Result<(), CodeError>>,
	shutdown_broadcast: broadcast::Sender<ShutdownSignal>,
	current_status: Arc<Mutex<Option<StatusInfo>>>,
	status_reports: watch::Sender<Option<ConnectionReporter>>,
}

impl RpcServer {
	fn set_current_status(&mut self, status: StatusInfo) {
		let mut changes = status.lock.subscribe();
		// Initial readiness is reported by startup, not by this reconnect observer.
		changes.borrow_and_update();
		let reporter = ConnectionReporter {
			name: status.name.clone(),
			tunnel_id: status.tunnel_id.clone(),
			status: changes,
		};
		*self.current_status.lock().unwrap() = Some(status);
		self.status_reports.send_replace(Some(reporter));
	}
}

pub fn make_singleton_server(
	log_broadcast: BroadcastLogSink,
	log: log::Logger,
	server: SingletonServer,
	shutdown_rx: Barrier<ShutdownSignal>,
) -> RpcServer {
	let (shutdown_broadcast, _) = broadcast::channel(4);
	let rpc = new_json_rpc();

	let current_status = Arc::new(Mutex::default());
	let (status_reports, status_reports_rx) = watch::channel(None);
	let mut rpc = rpc.methods(SingletonServerContext {
		log: log.clone(),
		shutdown_tx: shutdown_broadcast.clone(),
		broadcast_tx: log_broadcast.get_brocaster(),
		current_status: current_status.clone(),
	});

	rpc.register_sync(
		protocol::singleton::METHOD_RESTART,
		|_: protocol::EmptyObject, ctx| {
			request_restart(ctx);
			Ok(())
		},
	);

	rpc.register_sync(
		protocol::singleton::METHOD_STATUS,
		|_: protocol::EmptyObject, c| {
			Ok(c.current_status
				.lock()
				.unwrap()
				.as_ref()
				.map(|s| protocol::singleton::StatusWithTunnelName {
					name: Some(s.name.clone()),
					tunnel_id: Some(s.tunnel_id.clone()),
					has_editor_link: Some(true),
					status: s.lock.read(),
				})
				.unwrap_or_default())
		},
	);

	rpc.register_sync(
		protocol::singleton::METHOD_SHUTDOWN,
		|_: protocol::EmptyObject, ctx| {
			info!(
				ctx.log,
				"closing tunnel and all clients after a shutdown request"
			);
			let _ = ctx.broadcast_tx.send(RpcCaller::serialize_notify(
				&JsonRpcSerializer {},
				protocol::singleton::METHOD_SHUTDOWN,
				protocol::EmptyObject {},
			));
			let _ = ctx.shutdown_tx.send(ShutdownSignal::RpcShutdownRequested);
			Ok(())
		},
	);

	// we tokio spawn instead of keeping a future, since we want it to progress
	// even outside of the start_singleton_server loop (i.e. while the tunnel restarts)
	let fut = tokio::spawn(async move {
		serve_singleton_rpc(
			log_broadcast,
			server,
			rpc.build(log.clone()),
			log,
			status_reports_rx,
			shutdown_rx,
		)
		.await
	});
	RpcServer {
		shutdown_broadcast,
		current_status,
		status_reports,
		fut,
	}
}

fn request_restart(ctx: &SingletonServerContext) {
	info!(ctx.log, "restarting tunnel after client request");
	if let Some(status) = ctx.current_status.lock().unwrap().as_ref() {
		status.lock.fail("Tunnel restart requested".to_string());
	}
	let _ = ctx.shutdown_tx.send(ShutdownSignal::RpcRestartRequested);
}

pub async fn start_singleton_server(
	args: SingletonServerArgs<'_>,
) -> Result<ServerTermination, AnyError> {
	let broadcast_tx = args.log_broadcast.get_brocaster();
	machine_status::install_sink(move |status| {
		let _ = broadcast_tx.send(RpcCaller::serialize_notify(
			&JsonRpcSerializer {},
			protocol::singleton::METHOD_MACHINE_STATUS,
			status,
		));
	});

	let shutdown_rx = ShutdownRequest::create_rx([
		ShutdownRequest::Derived(Box::new(args.server.shutdown_broadcast.subscribe())),
		ShutdownRequest::Derived(Box::new(args.shutdown.clone())),
	]);

	{
		args.server.set_current_status(StatusInfo {
			name: args.tunnel.name.clone(),
			tunnel_id: args.tunnel.id.clone(),
			lock: args.tunnel.status(),
		});
		print_listening(&args.log, &args.tunnel.name, true);
	}

	let serve_fut = super::serve(
		&args.log,
		args.tunnel,
		args.paths,
		args.code_server_args,
		args.platform,
		AgentHostServeOptions {
			user_data_dir: args.user_data_dir,
			delegate_to_editor: args.delegate_to_editor,
		},
		shutdown_rx,
	);

	pin!(serve_fut);

	match futures::future::select(Pin::new(&mut args.server.fut), &mut serve_fut).await {
		Either::Left((rpc_result, fut)) => {
			// the rpc server will only end as a result of a graceful shutdown, or
			// with an error. Return the result of the eventual shutdown of the
			// control server.
			rpc_result.unwrap()?;
			fut.await
		}
		Either::Right((ctrl_result, _)) => ctrl_result,
	}
}

async fn serve_singleton_rpc<C: Clone + Send + Sync + 'static>(
	log_broadcast: BroadcastLogSink,
	mut server: SingletonServer,
	dispatcher: RpcDispatcher<JsonRpcSerializer, C>,
	log: log::Logger,
	status_reports: watch::Receiver<Option<ConnectionReporter>>,
	shutdown_rx: Barrier<ShutdownSignal>,
) -> Result<(), CodeError> {
	let mut own_shutdown = shutdown_rx.clone();
	let shutdown_fut = own_shutdown.wait();
	pin!(shutdown_fut);
	let reports = report_reconnections(log, status_reports);
	pin!(reports);

	loop {
		let cnx = tokio::select! {
			c = server.accept() => c?,
			_ = &mut shutdown_fut => return Ok(()),
			_ = &mut reports => return Ok(()),
		};

		let (read, write) = socket_stream_split(cnx);
		let dispatcher = dispatcher.clone();
		let msg_rx = log_broadcast.replay_and_subscribe();
		let shutdown_rx = shutdown_rx.clone();
		tokio::spawn(async move {
			let _ = start_json_rpc(dispatcher.clone(), read, write, msg_rx, shutdown_rx).await;
		});
	}
}

async fn report_reconnections(
	log: log::Logger,
	mut reports: watch::Receiver<Option<ConnectionReporter>>,
) {
	loop {
		let next = reports.borrow_and_update().clone();
		let Some(mut reporter) = next else {
			if reports.changed().await.is_err() {
				return;
			}
			continue;
		};

		loop {
			tokio::select! {
				biased;
				changed = reports.changed() => {
					if changed.is_err() {
						return;
					}
					break;
				},
				changed = reporter.status.changed() => {
					if changed.is_err() {
						if reports.changed().await.is_err() {
							return;
						}
						break;
					}
					let connected = matches!(
						reporter.status.borrow_and_update().tunnel,
						protocol::singleton::TunnelState::Connected
					);
					if connected {
						print_listening(&log, &reporter.name, true);
						machine_status::emit_connected(
							&reporter.name, Some(&reporter.tunnel_id), false, true,
						);
					}
				}
			}
		}
	}
}

/// Log sink that can broadcast and replay log events. Used for transmitting
/// logs from the singleton to all clients. This should be created and injected
/// into other services, like the tunnel, before `start_singleton_server`
/// is called.
#[derive(Clone)]
pub struct BroadcastLogSink {
	recent: Arc<Mutex<RingBuffer<Vec<u8>>>>,
	tx: broadcast::Sender<Vec<u8>>,
}

impl Default for BroadcastLogSink {
	fn default() -> Self {
		Self::new()
	}
}

impl BroadcastLogSink {
	pub fn new() -> Self {
		let (tx, _) = broadcast::channel(64);
		Self {
			tx,
			recent: Arc::new(Mutex::new(RingBuffer::new(50))),
		}
	}

	pub fn get_brocaster(&self) -> broadcast::Sender<Vec<u8>> {
		self.tx.clone()
	}

	fn replay_and_subscribe(
		&self,
	) -> ConcatReceivable<Vec<u8>, mpsc::UnboundedReceiver<Vec<u8>>, broadcast::Receiver<Vec<u8>>>
	{
		let (log_replay_tx, log_replay_rx) = mpsc::unbounded_channel();

		for log in self.recent.lock().unwrap().iter() {
			let _ = log_replay_tx.send(log.clone());
		}

		let _ = log_replay_tx.send(RpcCaller::serialize_notify(
			&JsonRpcSerializer {},
			protocol::singleton::METHOD_LOG_REPLY_DONE,
			protocol::EmptyObject {},
		));

		ConcatReceivable::new(log_replay_rx, self.tx.subscribe())
	}
}

impl log::LogSink for BroadcastLogSink {
	fn write_log(&self, level: log::Level, prefix: &str, message: &str) {
		let s = JsonRpcSerializer {};
		let serialized = RpcCaller::serialize_notify(
			&s,
			protocol::singleton::METHOD_LOG,
			protocol::singleton::LogMessage {
				level: Some(level),
				prefix,
				message,
			},
		);

		let _ = self.tx.send(serialized.clone());
		self.recent.lock().unwrap().push(serialized);
	}

	fn write_result(&self, message: &str) {
		self.write_log(log::Level::Info, "", message);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tunnels::protocol::singleton::TunnelState;

	#[test]
	fn restart_marks_disconnected_before_relay_cleanup_can_block() {
		let status = StatusLock::default();
		status.succeed();
		let (shutdown_tx, mut shutdown_rx) = broadcast::channel(4);
		let (broadcast_tx, _) = broadcast::channel(4);
		let ctx = SingletonServerContext {
			log: log::Logger::test(),
			shutdown_tx,
			broadcast_tx,
			current_status: Arc::new(Mutex::new(Some(StatusInfo {
				name: "test-host".to_string(),
				tunnel_id: "test-id".to_string(),
				lock: status.clone(),
			}))),
		};

		request_restart(&ctx);

		assert!(matches!(status.read().tunnel, TunnelState::Disconnected));
		assert_eq!(
			status.read().last_fail_reason.as_deref(),
			Some("Tunnel restart requested")
		);
		assert!(matches!(
			shutdown_rx.try_recv().unwrap(),
			ShutdownSignal::RpcRestartRequested
		));
	}
}
