//! One selected original inbound queue and neutral full application-read facts.
//! This is not transport authentication, a physical receipt, or ACK authority.

use super::RelayMessage;
use crate::error::{RelayError, Result};
#[cfg(test)]
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

/// Opaque original full payload read. Only the original readers can capture it.
#[derive(Debug)]
pub struct OriginalRelayFrameRead {
    completed_at: Instant,
}

impl OriginalRelayFrameRead {
    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }
}

/// Original bytes and their neutral read fact move together through the queue.
#[derive(Debug)]
pub struct OriginalRelayDelivery {
    message: RelayMessage,
    read: Option<OriginalRelayFrameRead>,
}

impl OriginalRelayDelivery {
    pub fn message(&self) -> &RelayMessage {
        &self.message
    }
    pub fn into_parts(self) -> (RelayMessage, Option<OriginalRelayFrameRead>) {
        (self.message, self.read)
    }
}

impl From<RelayMessage> for OriginalRelayDelivery {
    fn from(message: RelayMessage) -> Self {
        Self {
            message,
            read: None,
        }
    }
}

#[derive(Clone, Copy)]
enum ReadMode {
    Legacy,
    Original,
}

pub(super) struct ReadOptions {
    mode: ReadMode,
    #[cfg(test)]
    witness: Option<Arc<OriginalRelayReadWitness>>,
}

impl ReadOptions {
    pub(super) fn legacy() -> Self {
        Self {
            mode: ReadMode::Legacy,
            #[cfg(test)]
            witness: None,
        }
    }
    pub(super) fn original() -> Self {
        Self {
            mode: ReadMode::Original,
            #[cfg(test)]
            witness: None,
        }
    }
    #[cfg(test)]
    pub(super) fn with_witness(witness: Arc<OriginalRelayReadWitness>) -> Self {
        Self {
            mode: ReadMode::Original,
            witness: Some(witness),
        }
    }
    #[cfg(test)]
    pub(super) fn witness(&self) -> Option<Arc<OriginalRelayReadWitness>> {
        self.witness.clone()
    }
    pub(super) fn channel(&self, capacity: usize) -> (ReadOutput, ReadInput) {
        match self.mode {
            ReadMode::Legacy => {
                let (tx, rx) = mpsc::channel(capacity);
                (ReadOutput::Legacy(tx), ReadInput::Legacy(rx))
            }
            ReadMode::Original => {
                let (tx, rx) = mpsc::channel(capacity);
                (ReadOutput::Original(tx), ReadInput::Original(rx))
            }
        }
    }
}

#[derive(Clone)]
pub(super) enum ReadOutput {
    Legacy(mpsc::Sender<RelayMessage>),
    Original(mpsc::Sender<OriginalRelayDelivery>),
}

pub(super) enum ReadInput {
    Legacy(mpsc::Receiver<RelayMessage>),
    Original(mpsc::Receiver<OriginalRelayDelivery>),
}

impl ReadInput {
    pub(super) fn into_legacy(self) -> Result<mpsc::Receiver<RelayMessage>> {
        match self {
            Self::Legacy(rx) => Ok(rx),
            Self::Original(_) => Err(RelayError::Protocol(
                "internal relay queue mode mismatch".into(),
            )),
        }
    }
    pub(super) fn into_original(self) -> Result<mpsc::Receiver<OriginalRelayDelivery>> {
        match self {
            Self::Original(rx) => Ok(rx),
            Self::Legacy(_) => Err(RelayError::Protocol(
                "internal relay queue mode mismatch".into(),
            )),
        }
    }
}

impl ReadOutput {
    // Called only in the two actual successful payload read branches, with no
    // intervening await/log/parse/copy. Legacy performs no new clock sample.
    pub(super) fn capture_data_read(&self) -> Option<OriginalRelayFrameRead> {
        match self {
            Self::Legacy(_) => None,
            Self::Original(_) => Some(OriginalRelayFrameRead {
                completed_at: Instant::now(),
            }),
        }
    }
    pub(super) async fn send_data(
        &self,
        message: RelayMessage,
        read: Option<OriginalRelayFrameRead>,
    ) -> std::result::Result<(), ()> {
        match self {
            Self::Legacy(tx) => {
                if read.is_some() {
                    return Err(());
                }
                tx.send(message).await.map_err(|_| ())
            }
            Self::Original(tx) => tx
                .send(OriginalRelayDelivery { message, read })
                .await
                .map_err(|_| ()),
        }
    }
    pub(super) fn try_send(&self, message: RelayMessage) -> std::result::Result<(), ()> {
        match self {
            Self::Legacy(tx) => tx.try_send(message).map_err(|_| ()),
            Self::Original(tx) => tx
                .try_send(OriginalRelayDelivery::from(message))
                .map_err(|_| ()),
        }
    }
}

/// One bounded unit-test witness, only for first valid Data from the real reader.
/// Private state/write entry; neither a synthetic time nor a source factory.
#[cfg(test)]
#[allow(dead_code)] // Staged library fixture API; not a cross-crate test feature.
pub(super) struct OriginalRelayReadWitness {
    captured_at: std::sync::OnceLock<Instant>,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by the separately authored library-only controls.
impl OriginalRelayReadWitness {
    pub(super) fn new() -> Self {
        Self {
            captured_at: std::sync::OnceLock::new(),
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        }
    }
    pub(super) fn completed_at(&self) -> Option<Instant> {
        self.captured_at.get().copied()
    }
    pub(super) async fn wait_captured(&self) {
        self.reached.notified().await;
    }
    pub(super) fn release(&self) {
        self.release.notify_one();
    }
    pub(super) async fn observe_once(&self, read: &OriginalRelayFrameRead) {
        if self.captured_at.set(read.completed_at()).is_ok() {
            self.reached.notify_one();
            self.release.notified().await;
        }
    }
}
