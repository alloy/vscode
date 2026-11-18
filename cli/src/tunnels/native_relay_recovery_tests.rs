/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy)]
enum TokenMode {
	Pending,
	Rejected,
	Valid,
	KeepAliveFinished,
	KeepAliveRejected,
	KeepAliveTransient,
}

struct Token(TokenMode);

impl AccessTokenProvider for Token {
	async fn refresh_token(&self) -> Result<String, WrappedError> {
		match self.0 {
			TokenMode::Pending => futures::future::pending().await,
			TokenMode::Rejected => Err(wrap("", "synthetic authentication rejection")),
			_ => Ok("synthetic-offline-token".to_string()),
		}
	}

	fn keep_alive(&self) -> BoxFuture<'static, Result<(), AnyError>> {
		match self.0 {
			TokenMode::KeepAliveFinished => futures::future::ready(Ok(())).boxed(),
			TokenMode::KeepAliveRejected | TokenMode::KeepAliveTransient => futures::future::ready(
				Err(DevTunnelError("synthetic rejection".to_string()).into()),
			)
			.boxed(),
			_ => futures::future::pending().boxed(),
		}
	}

	fn authentication_required(&self) -> bool {
		matches!(self.0, TokenMode::Rejected | TokenMode::KeepAliveRejected)
	}
}

struct Fixture {
	task: tokio::task::JoinHandle<()>,
	close: Option<mpsc::Sender<()>>,
	status: StatusLock,
	attempts: Arc<AtomicUsize>,
}

impl Fixture {
	async fn new(
		token: TokenMode,
		blocked_connect: bool,
		failed_close: bool,
		blocked_close: bool,
	) -> Self {
		let (close, close_rx) = mpsc::channel(1);
		let (endpoint_tx, _) = watch::channel(None);
		let attempts = Arc::new(AtomicUsize::new(0));
		let connect_attempts = attempts.clone();
		let status = StatusLock::default();
		let task = tokio::spawn(ActiveTunnelManager::run_tunnel(
			log::Logger::test(),
			move |_| {
				connect_attempts.fetch_add(1, Ordering::SeqCst);
				async move {
					if blocked_connect {
						futures::future::pending::<()>().await;
					}
					Ok(futures::future::pending::<Result<(), WrappedError>>())
				}
				.boxed()
			},
			|_| {
				serde_json::from_value(serde_json::json!({
					"connectionMode": "TunnelRelay", "hostId": "synthetic-host"
				}))
				.unwrap()
			},
			move |_| async move {
				if blocked_close {
					futures::future::pending::<()>().await;
				}
				if failed_close {
					Err(wrap("", "synthetic close failure"))
				} else {
					Ok(())
				}
			},
			close_rx,
			endpoint_tx,
			Token(token),
			status.clone(),
		));
		let fixture = Self {
			task,
			close: Some(close),
			status,
			attempts,
		};
		Self::settle().await;
		fixture
	}

	async fn settle() {
		for _ in 0..8 {
			tokio::task::yield_now().await;
		}
	}

	async fn shutdown(mut self) {
		drop(self.close.take());
		tokio::time::timeout(Duration::from_secs(1), &mut self.task)
			.await
			.unwrap()
			.unwrap();
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		self.task.abort();
	}
}

#[tokio::test(start_paused = true)]
async fn shutdown_cancels_pending_token_acquisition() {
	let fixture = Fixture::new(TokenMode::Pending, false, false, false).await;
	assert_eq!(fixture.attempts.load(Ordering::SeqCst), 0);
	fixture.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn shutdown_cancels_pending_connection() {
	let fixture = Fixture::new(TokenMode::Valid, true, false, false).await;
	assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
	fixture.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn authentication_wait_is_cancellable_and_explicit() {
	let fixture = Fixture::new(TokenMode::Rejected, false, false, false).await;
	assert_eq!(
		fixture.status.read().recovery,
		Some(protocol::singleton::RecoveryState::AuthenticationRequired)
	);
	fixture.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn token_acquisition_timeout_reports_retry_instead_of_hanging() {
	let fixture = Fixture::new(TokenMode::Pending, false, false, false).await;
	tokio::time::advance(TOKEN_REFRESH_TIMEOUT).await;
	Fixture::settle().await;
	assert!(fixture
		.status
		.read()
		.last_fail_reason
		.unwrap()
		.contains("timed out acquiring"));
	assert_eq!(
		fixture.status.read().recovery,
		Some(protocol::singleton::RecoveryState::Retrying)
	);
	fixture.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn connection_timeout_reports_retry_instead_of_hanging() {
	let fixture = Fixture::new(TokenMode::Valid, true, false, false).await;
	tokio::time::advance(RELAY_CONNECT_TIMEOUT).await;
	Fixture::settle().await;
	assert!(fixture
		.status
		.read()
		.last_fail_reason
		.unwrap()
		.contains("timed out connecting"));
	fixture.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn successful_keepalive_completion_is_not_repolled() {
	let fixture = Fixture::new(TokenMode::KeepAliveFinished, false, false, false).await;
	Fixture::settle().await;
	assert!(!fixture.task.is_finished());
	assert!(matches!(
		fixture.status.read().tunnel,
		protocol::singleton::TunnelState::Connected
	));
	fixture.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn failed_cleanup_refuses_duplicate_relay() {
	let mut fixture = Fixture::new(TokenMode::KeepAliveRejected, false, true, false).await;
	(&mut fixture.task).await.unwrap();
	assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
	assert_eq!(
		fixture.status.read().recovery,
		Some(protocol::singleton::RecoveryState::Failed)
	);
}

#[tokio::test(start_paused = true)]
async fn credential_worker_failure_is_not_mislabeled_as_invalid_authentication() {
	let fixture = Fixture::new(TokenMode::KeepAliveTransient, false, false, false).await;
	assert_eq!(
		fixture.status.read().recovery,
		Some(protocol::singleton::RecoveryState::Retrying)
	);
	assert!(!fixture
		.status
		.read()
		.last_fail_reason
		.unwrap()
		.contains("no longer valid"));
	fixture.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn blocked_cleanup_remains_visible_without_starting_a_duplicate() {
	let fixture = Fixture::new(TokenMode::KeepAliveRejected, false, false, true).await;
	tokio::time::advance(RELAY_CLEANUP_TIMEOUT).await;
	Fixture::settle().await;
	assert_eq!(
		fixture.status.read().recovery,
		Some(protocol::singleton::RecoveryState::CleanupBlocked)
	);
	assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
	assert!(!fixture.task.is_finished());
}

#[tokio::test(start_paused = true)]
async fn credential_maintenance_keeps_running_during_relay_backoff() {
	struct Maintenance {
		wake: Arc<tokio::sync::Notify>,
		progress: Arc<AtomicUsize>,
	}
	impl AccessTokenProvider for Maintenance {
		async fn refresh_token(&self) -> Result<String, WrappedError> {
			Ok("synthetic-offline-token".to_string())
		}

		fn keep_alive(&self) -> BoxFuture<'static, Result<(), AnyError>> {
			let wake = self.wake.clone();
			let progress = self.progress.clone();
			async move {
				progress.fetch_add(1, Ordering::SeqCst);
				wake.notified().await;
				progress.fetch_add(1, Ordering::SeqCst);
				futures::future::pending().await
			}
			.boxed()
		}
	}
	let wake = Arc::new(tokio::sync::Notify::new());
	let progress = Arc::new(AtomicUsize::new(0));
	let (end, end_rx) = tokio::sync::oneshot::channel::<Result<(), WrappedError>>();
	let mut first = Some(end_rx);
	let (close, close_rx) = mpsc::channel(1);
	let (endpoint_tx, mut endpoint_rx) = watch::channel(None);
	let status = StatusLock::default();
	let task = tokio::spawn(ActiveTunnelManager::run_tunnel(
		log::Logger::test(),
		move |_| {
			let relay: BoxFuture<'static, Result<(), WrappedError>> = match first.take() {
				Some(end) => async move { end.await.unwrap() }.boxed(),
				None => futures::future::pending().boxed(),
			};
			futures::future::ready(Ok(relay)).boxed()
		},
		|_| {
			serde_json::from_value(serde_json::json!({
				"connectionMode": "TunnelRelay", "hostId": "synthetic-host"
			}))
			.unwrap()
		},
		|_| futures::future::ready(Ok(())),
		close_rx,
		endpoint_tx,
		Maintenance {
			wake: wake.clone(),
			progress: progress.clone(),
		},
		status.clone(),
	));
	let fixture = Fixture {
		task,
		close: Some(close),
		status,
		attempts: Arc::new(AtomicUsize::new(0)),
	};
	endpoint_rx.changed().await.unwrap();
	Fixture::settle().await;
	assert_eq!(progress.load(Ordering::SeqCst), 1);
	end.send(Err(wrap("", "synthetic relay exit"))).unwrap();
	endpoint_rx.changed().await.unwrap();
	wake.notify_one();
	Fixture::settle().await;
	assert_eq!(
		progress.load(Ordering::SeqCst),
		2,
		"credential work must not stall or restart with relay backoff"
	);
	fixture.shutdown().await;
}
