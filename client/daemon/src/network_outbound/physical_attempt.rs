// Sole original emit owner OUTSIDE the cancellable bounded send future.
// The inner future borrows capture and owns all its epoch/slot/registry guards;
// Rust ends that borrow by destroying inner before this owner's destructor.
use crate::overlay_requests::{PhysicalRequestPublisher, PreparedPhysicalPublication};
use crate::udp::UdpSendCapture;

pub(super) struct PhysicalAttempt<G> {
    emit: Option<G>,
    publisher: Option<PhysicalRequestPublisher>,
    capture: UdpSendCapture,
}
impl<G> PhysicalAttempt<G> {
    pub(super) fn new(emit: G, prepared: Option<PreparedPhysicalPublication>) -> Self {
        Self {
            emit: Some(emit),
            publisher: prepared.and_then(|prepared| prepared.open().ok()),
            capture: UdpSendCapture::new(),
        }
    }
    pub(super) fn arm(&mut self, prepared: Option<PreparedPhysicalPublication>) {
        self.publisher = prepared.and_then(|prepared| prepared.open().ok());
    }
    pub(super) fn capture(&mut self) -> Option<&mut UdpSendCapture> {
        if self.publisher.is_some() {
            Some(&mut self.capture)
        } else {
            None
        }
    }
    pub(super) fn finish(&mut self, definitely_not_handed: bool) {
        // The original slow Arc has no clones; fast owns the guard directly.
        // Release emit before publishing, including external future cancellation.
        drop(self.emit.take());
        if let Some(publisher) = self.publisher.as_mut() {
            if let Some(fact) = self.capture.take() {
                let _ = publisher.publish(fact);
            }
            // A captured full success wins before our own matching Open cancel.
            // An external terminal may already have won and stays uncertain.
            publisher.finish(definitely_not_handed);
        }
        self.publisher.take();
    }
}
impl<G> Drop for PhysicalAttempt<G> {
    fn drop(&mut self) {
        self.finish(false);
    }
}
