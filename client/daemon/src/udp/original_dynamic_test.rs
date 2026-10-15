//! Test ownership transfer of a removed original entry, never current state.
use super::*;

pub(crate) struct OriginalDynamicRetirementForTest {
    entry: Option<DynamicPunchSocket>,
}

impl OriginalDynamicRetirementForTest {
    pub(super) fn from_entry(entry: DynamicPunchSocket) -> Self {
        Self { entry: Some(entry) }
    }
    pub(crate) async fn stop_and_join(
        &mut self,
        transport: &UdpTransport,
    ) -> std::result::Result<(), tokio::task::JoinError> {
        let Some(entry) = self.entry.as_mut() else {
            return Ok(());
        };
        transport
            .stop_original_dynamic_entry(entry, "original_ack_owned_retirement")
            .await;
        let result = match (&mut entry.reader).await {
            Err(error) if error.is_cancelled() => Ok(()),
            other => other,
        };
        // Remove only after the original handle completed. Cancellation while
        // awaiting leaves it in this one original retired owner for cleanup.
        self.entry.take();
        result
    }
    pub(crate) fn is_joined(&self) -> bool {
        self.entry.is_none()
    }
}

impl Drop for OriginalDynamicRetirementForTest {
    fn drop(&mut self) {
        if let Some(entry) = &self.entry {
            entry.shutdown_tx.send_replace(true);
            entry.reader.abort();
        }
    }
}

impl UdpTransport {
    pub(crate) async fn take_original_dynamic_retirement_for_test(
        &self,
        index: usize,
    ) -> Option<OriginalDynamicRetirementForTest> {
        self.remove_original_dynamic_entry(index)
            .await
            .map(|entry| OriginalDynamicRetirementForTest { entry: Some(entry) })
    }
    pub(crate) async fn original_dynamic_count_for_test(&self) -> usize {
        self.socket_state.lock().await.dynamic.len()
    }
    pub(crate) async fn with_original_socket_state_held_for_test<R>(
        &self,
        operation: impl FnOnce() -> R,
    ) -> R {
        let _guard = self.socket_state.lock().await;
        operation()
    }
}

/// A slot owned before calling the original attach. It contains only actual
/// spawned/removed handles; it never represents current socket publication.
#[derive(Default)]
pub(crate) struct OriginalDynamicAttachForTest {
    pub(super) guard: Option<ProvisionalSocketGuard>,
    pub(super) reader: Option<tokio::task::JoinHandle<()>>,
    pub(super) retired: Vec<OriginalDynamicRetirementForTest>,
}

impl OriginalDynamicAttachForTest {
    pub(crate) fn original_guard(&self) -> Option<&ProvisionalSocketGuard> {
        self.guard.as_ref()
    }
    pub(super) fn signal_stop(&self) {
        if let Some(guard) = &self.guard {
            guard.signal_original_watcher_stop_for_test();
        }
        if let Some(reader) = &self.reader {
            reader.abort();
        }
    }
    pub(crate) fn is_joined(&self) -> bool {
        self.reader.is_none()
            && self
                .guard
                .as_ref()
                .is_none_or(|guard| guard.original_watcher_joined_for_test())
            && self.retired.iter().all(|entry| entry.is_joined())
    }
    pub(crate) async fn stop_and_join(
        &mut self,
        transport: &UdpTransport,
    ) -> std::result::Result<(), String> {
        self.signal_stop();
        let mut failures = Vec::new();
        if let Some(reader) = self.reader.as_mut() {
            if let Err(error) = reader.await {
                if !error.is_cancelled() {
                    failures.push(format!("original pending reader join: {error}"));
                }
            }
            self.reader.take();
        }
        if let Some(guard) = self.guard.as_mut() {
            if let Err(error) = guard.join_original_watcher_for_test().await {
                failures.push(format!("original watcher join: {error}"));
            }
        }
        for entry in &mut self.retired {
            if let Err(error) = entry.stop_and_join(transport).await {
                failures.push(format!("original evicted reader join: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}
impl Drop for OriginalDynamicAttachForTest {
    fn drop(&mut self) {
        self.signal_stop();
    }
}

impl UdpTransport {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn attach_dynamic_owned_for_test(
        &self,
        peer: &str,
        index: usize,
        socket: Arc<UdpSocket>,
        generation: u64,
        punch: u64,
        cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
        owner: &mut OriginalDynamicAttachForTest,
    ) -> std::result::Result<(), DynamicSocketAttachError> {
        if owner.guard.is_some() || owner.reader.is_some() || !owner.retired.is_empty() {
            return Err(DynamicSocketAttachError::Superseded);
        }
        if let Some(guard) = self
            .attach_original_dynamic_inner(
                peer,
                index,
                socket,
                generation,
                punch,
                cancellation,
                Some(&mut *owner),
            )
            .await?
        {
            owner.guard = Some(guard);
        }
        Ok(())
    }
}
