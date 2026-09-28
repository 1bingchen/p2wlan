//! Consume already-authorized JNI edges in publication order. Kotlin's counter
//! may restart with a service owner, so it is never used as a global clock here.

use crate::{AndroidNetworkChangeHint, AndroidNetworkChangeReceiver};
use tokio::sync::broadcast;

const MAX_HINTS_PER_DRAIN: usize = 64;

fn drain_latest(
    receiver: &mut broadcast::Receiver<AndroidNetworkChangeHint>,
    mut latest: Option<AndroidNetworkChangeHint>,
) -> Option<AndroidNetworkChangeHint> {
    let mut coalesced = 0usize;
    for _ in 0..MAX_HINTS_PER_DRAIN {
        match receiver.try_recv() {
            Ok(hint) => {
                coalesced += usize::from(latest.is_some());
                latest = Some(hint);
            }
            Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
            Err(_) => break,
        }
    }
    if coalesced > 0 {
        tracing::debug!(
            event = "android_network_hints_coalesced",
            coalesced,
            "Coalesced queued authorized physical-network edges"
        );
    }
    latest
}

pub(crate) async fn take_latest(
    receiver: &AndroidNetworkChangeReceiver,
) -> Option<AndroidNetworkChangeHint> {
    drain_latest(&mut *receiver.lock().await, None)
}

pub(crate) async fn recv_latest(
    receiver: &AndroidNetworkChangeReceiver,
) -> Option<AndroidNetworkChangeHint> {
    let mut receiver = receiver.lock().await;
    loop {
        match receiver.recv().await {
            Ok(hint) => return drain_latest(&mut receiver, Some(hint)),
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn queued_edges_keep_publication_order_across_service_counter_reset() {
        let (tx, rx) = broadcast::channel(32);
        let rx = Arc::new(Mutex::new(rx));
        for (generation, hash) in [(40, "previous-service"), (1, "new-service")] {
            tx.send(AndroidNetworkChangeHint {
                kotlin_network_generation: generation,
                network_identity_hash: hash.into(),
            })
            .unwrap();
        }
        let latest = recv_latest(&rx).await.unwrap();
        assert_eq!(latest.kotlin_network_generation, 1);
        assert_eq!(latest.network_identity_hash, "new-service");
        assert!(take_latest(&rx).await.is_none());
    }
}
