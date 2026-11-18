/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::*;
use std::{
	collections::VecDeque,
	pin::Pin,
	task::{Context, Poll},
};
use tokio::{sync::oneshot, task::JoinHandle};

struct ControlledToken {
	failure: Mutex<Option<oneshot::Receiver<()>>>,
	rejected: Arc<std::sync::atomic::AtomicBool>,
}

impl AccessTokenProvider for ControlledToken {
	async fn refresh_token(&self) -> Result<String, WrappedError> {
		Ok("synthetic-offline-token".to_string())
	}

	fn keep_alive(&self) -> BoxFuture<'static, Result<(), AnyError>> {
		let Some(failure) = self.failure.lock().unwrap().take() else {
			return futures::future::pending().boxed();
		};
		let rejected = self.rejected.clone();
		async move {
			let _ = failure.await;
			rejected.store(true, std::sync::atomic::Ordering::SeqCst);
			Err(DevTunnelError("synthetic-keepalive-rejected".to_string()).into())
		}
		.boxed()
	}

	fn authentication_required(&self) -> bool {
		self.rejected.load(std::sync::atomic::Ordering::SeqCst)
	}
}

struct ControlledHandle {
	end: oneshot::Receiver<Result<(), WrappedError>>,
	close_started: Option<oneshot::Sender<()>>,
	close_release: oneshot::Receiver<()>,
}

impl Future for ControlledHandle {
	type Output = Result<(), WrappedError>;

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		Pin::new(&mut self.end)
			.poll(cx)
			.map(|result| result.expect("relay controller must stay alive"))
	}
}

struct RelayControl {
	end: Option<oneshot::Sender<Result<(), WrappedError>>>,
	close_started: Option<oneshot::Receiver<()>>,
	close_release: Option<oneshot::Sender<()>>,
}

struct Fixture {
	task: JoinHandle<()>,
	status: StatusLock,
	endpoint: watch::Receiver<Option<Result<TunnelEndpoint, WrappedError>>>,
	close: Option<mpsc::Sender<()>>,
	token_failure: Option<oneshot::Sender<()>>,
	relays: Vec<RelayControl>,
}

impl Drop for Fixture {
	fn drop(&mut self) {
		self.task.abort();
	}
}

impl Fixture {
	async fn connected() -> Self {
		let (close, close_rx) = mpsc::channel(1);
		let (endpoint_tx, endpoint) = watch::channel(None);
		let (token_failure, failure_rx) = oneshot::channel();
		let mut handles = VecDeque::new();
		let mut relays = Vec::new();
		for _ in 0..2 {
			let (end, end_rx) = oneshot::channel();
			let (close_started, close_started_rx) = oneshot::channel();
			let (close_release, close_release_rx) = oneshot::channel();
			handles.push_back(ControlledHandle {
				end: end_rx,
				close_started: Some(close_started),
				close_release: close_release_rx,
			});
			relays.push(RelayControl {
				end: Some(end),
				close_started: Some(close_started_rx),
				close_release: Some(close_release),
			});
		}
		let status = StatusLock::default();
		let task = tokio::spawn(ActiveTunnelManager::run_tunnel(
			log::Logger::test(),
			move |_| futures::future::ready(Ok(handles.pop_front().unwrap())).boxed(),
			|_: &ControlledHandle| {
				serde_json::from_value(serde_json::json!({
					"connectionMode": "TunnelRelay",
					"hostId": "offline-regression-host"
				}))
				.unwrap()
			},
			|mut handle: ControlledHandle| async move {
				handle.close_started.take().unwrap().send(()).unwrap();
				let _ = handle.close_release.await;
				Ok(())
			},
			close_rx,
			endpoint_tx,
			ControlledToken {
				failure: Mutex::new(Some(failure_rx)),
				rejected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
			},
			status.clone(),
		));
		let mut fixture = Self {
			task,
			status,
			endpoint,
			close: Some(close),
			token_failure: Some(token_failure),
			relays,
		};
		tokio::time::timeout(Duration::from_secs(2), fixture.endpoint.changed())
			.await
			.unwrap()
			.unwrap();
		assert!(fixture.endpoint.borrow().as_ref().unwrap().is_ok());
		assert!(matches!(
			fixture.status.read().tunnel,
			protocol::singleton::TunnelState::Connected
		));
		fixture
	}

	async fn settle() {
		for _ in 0..8 {
			tokio::task::yield_now().await;
		}
	}

	fn assert_disconnected(&self, reason: &str) {
		let state = self.status.read();
		assert!(
			matches!(state.tunnel, protocol::singleton::TunnelState::Disconnected),
			"expected Disconnected, got {:?}",
			state.tunnel
		);
		assert!(state.last_disconnected_at.is_some());
		assert!(
			state.last_fail_reason.as_deref().unwrap().contains(reason),
			"failure reason must retain {reason:?}: {:?}",
			state.last_fail_reason
		);
	}
}

#[tokio::test]
async fn keepalive_failure_updates_status_and_endpoint_observer() {
	let mut fixture = Fixture::connected().await;
	fixture.token_failure.take().unwrap().send(()).unwrap();
	tokio::time::timeout(Duration::from_secs(2), fixture.endpoint.changed())
		.await
		.unwrap()
		.unwrap();
	assert!(
		!fixture.task.is_finished(),
		"the worker must remain available for recovery"
	);
	fixture.assert_disconnected("synthetic-keepalive-rejected");
	let observed = fixture.endpoint.borrow();
	let error = observed
		.as_ref()
		.unwrap()
		.as_ref()
		.expect_err("an endpoint observer must not retain a successful endpoint");
	assert!(error.to_string().contains("synthetic-keepalive-rejected"));
	assert!(error
		.to_string()
		.contains("access token is no longer valid"));
	drop(observed);
	fixture.relays[0]
		.close_release
		.take()
		.unwrap()
		.send(())
		.unwrap();
	tokio::time::timeout(Duration::from_secs(8), fixture.endpoint.changed())
		.await
		.unwrap()
		.unwrap();
	assert!(fixture.endpoint.borrow().as_ref().unwrap().is_ok());
}

#[tokio::test]
async fn graceful_relay_exit_disconnects_before_backoff_and_reconnects() {
	let mut fixture = Fixture::connected().await;
	let initial = fixture.status.read().last_connected_at.unwrap();
	fixture.relays[0].end.take().unwrap().send(Ok(())).unwrap();
	Fixture::settle().await;
	fixture.assert_disconnected("gracefully");
	assert!(!fixture.endpoint.has_changed().unwrap());
	tokio::time::timeout(Duration::from_secs(8), fixture.endpoint.changed())
		.await
		.unwrap()
		.unwrap();
	let state = fixture.status.read();
	assert!(matches!(
		state.tunnel,
		protocol::singleton::TunnelState::Connected
	));
	assert!(state.last_connected_at.unwrap() > initial);
}

#[tokio::test]
async fn error_relay_exit_notifies_before_backoff() {
	let mut fixture = Fixture::connected().await;
	fixture.relays[0]
		.end
		.take()
		.unwrap()
		.send(Err(wrap("synthetic-relay-error", "relay failed")))
		.unwrap();
	tokio::time::timeout(Duration::from_secs(2), fixture.endpoint.changed())
		.await
		.unwrap()
		.unwrap();
	fixture.assert_disconnected("synthetic-relay-error");
	assert!(fixture.endpoint.borrow().as_ref().unwrap().is_err());
}

#[tokio::test]
async fn cancelling_actual_worker_disconnects() {
	let mut fixture = Fixture::connected().await;
	fixture.task.abort();
	assert!((&mut fixture.task).await.unwrap_err().is_cancelled());
	fixture.assert_disconnected("Tunnel relay task stopped");
}

#[tokio::test]
async fn cancelling_failed_worker_preserves_specific_reason() {
	let mut fixture = Fixture::connected().await;
	fixture.relays[0]
		.end
		.take()
		.unwrap()
		.send(Err(wrap("specific-failure", "relay failed")))
		.unwrap();
	fixture.endpoint.changed().await.unwrap();
	let before = fixture.status.read();
	fixture.task.abort();
	assert!((&mut fixture.task).await.unwrap_err().is_cancelled());
	let after = fixture.status.read();
	assert_eq!(after.last_fail_reason, before.last_fail_reason);
	assert_eq!(after.last_disconnected_at, before.last_disconnected_at);
	fixture.assert_disconnected("specific-failure");
}

#[tokio::test]
async fn close_completion_disconnects_actual_worker() {
	let mut fixture = Fixture::connected().await;
	drop(fixture.close.take());
	fixture.relays[0]
		.close_started
		.take()
		.unwrap()
		.await
		.unwrap();
	fixture.relays[0]
		.close_release
		.take()
		.unwrap()
		.send(())
		.unwrap();
	tokio::time::timeout(Duration::from_secs(2), &mut fixture.task)
		.await
		.unwrap()
		.unwrap();
	fixture.assert_disconnected("Tunnel relay task stopped");
}

#[tokio::test]
async fn close_request_disconnects_before_blocked_cleanup() {
	let mut fixture = Fixture::connected().await;
	drop(fixture.close.take());
	tokio::time::timeout(
		Duration::from_secs(2),
		fixture.relays[0].close_started.take().unwrap(),
	)
	.await
	.unwrap()
	.unwrap();
	fixture.assert_disconnected("Tunnel");
}

#[tokio::test]
async fn reconnect_after_disconnected_attachment_produces_readiness() {
	let mut fixture = Fixture::connected().await;
	fixture.relays[0].end.take().unwrap().send(Ok(())).unwrap();
	Fixture::settle().await;
	crate::tunnels::singleton_server::stale_health_regression::assert_connection_produces_readiness(
		fixture.status.clone(),
		async {
			tokio::time::timeout(Duration::from_secs(8), fixture.endpoint.changed())
				.await
				.unwrap()
				.unwrap();
		},
	)
	.await;
}

#[tokio::test]
async fn old_worker_cleanup_cannot_disconnect_replacement_manager() {
	let mut old = Fixture::connected().await;
	let replacement = Fixture::connected().await;
	old.task.abort();
	assert!((&mut old.task).await.unwrap_err().is_cancelled());
	assert!(matches!(
		replacement.status.read().tunnel,
		protocol::singleton::TunnelState::Connected
	));
}
