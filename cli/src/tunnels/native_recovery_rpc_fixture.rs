/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::*;
use crate::util::sync::{new_barrier, BarrierOpener};

pub(in crate::tunnels) struct NativeRecoveryRpc {
	server: RpcServer,
	_shutdown: BarrierOpener<ShutdownSignal>,
}

impl Drop for NativeRecoveryRpc {
	fn drop(&mut self) {
		self._shutdown.open(ShutdownSignal::RpcShutdownRequested);
		self.server.fut.abort();
		machine_status::install_sink(|_| {});
	}
}

impl NativeRecoveryRpc {
	pub(in crate::tunnels) async fn stop(&mut self) {
		self._shutdown.open(ShutdownSignal::RpcShutdownRequested);
		let _ = (&mut self.server.fut).await;
	}
}

pub(in crate::tunnels) fn serve(
	singleton: SingletonServer,
	status: StatusLock,
	broadcast: BroadcastLogSink,
) -> NativeRecoveryRpc {
	let (shutdown, opener) = new_barrier();
	let log = log::Logger::test().with_sink(broadcast.clone());
	let mut server = make_singleton_server(broadcast.clone(), log, singleton, shutdown);
	server.set_current_status(StatusInfo {
		name: "native-recovery-demo".to_string(),
		tunnel_id: "synthetic-sdk-tunnel".to_string(),
		lock: status,
	});
	let tx = broadcast.get_brocaster();
	machine_status::install_sink(move |event| {
		let _ = tx.send(RpcCaller::serialize_notify(
			&JsonRpcSerializer {},
			protocol::singleton::METHOD_MACHINE_STATUS,
			event,
		));
	});
	NativeRecoveryRpc {
		server,
		_shutdown: opener,
	}
}
