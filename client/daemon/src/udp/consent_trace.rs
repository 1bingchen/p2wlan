//! Fixture-only, bounded observations of the actual legacy ACK transaction.
//! Recording has no await, callback, notification, retry or protocol authority.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConsentStage {
    SendReturned,
    AckDecoded,
    PendingLookup,
    NoPeerOwnedPending,
    AdoptionAcquired,
    EpochAcquired,
    Expired,
    CleanupChanged,
    Matched,
    StampsChanged,
    EndpointRejected,
    HealthCommitted,
    HealthRejected,
    Mismatch,
    RoundRemovedPending,
    RoundPendingAbsent,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ConsentEvent {
    pub(super) nonce: ProbeNonce,
    pub(super) elapsed: Duration,
    pub(super) stage: ConsentStage,
}

pub(super) struct ConsentTrace {
    start: Instant,
    events: StdMutex<[Option<ConsentEvent>; 32]>,
    dropped: AtomicU64,
}

impl ConsentTrace {
    pub(super) fn new() -> Self {
        Self {
            start: Instant::now(),
            events: StdMutex::new([None; 32]),
            dropped: AtomicU64::new(0),
        }
    }

    fn record(&self, nonce: ProbeNonce, stage: ConsentStage) {
        // Read time only after admission to the observation lock: event order
        // and elapsed order agree even if concurrent readers were preempted.
        // Busy/poisoned/full means missing evidence, never a protocol wait.
        if let Ok(mut events) = self.events.try_lock() {
            if let Some(slot) = events.iter_mut().find(|event| event.is_none()) {
                *slot = Some(ConsentEvent {
                    nonce,
                    elapsed: self.start.elapsed(),
                    stage,
                });
                return;
            }
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot(&self) -> ([Option<ConsentEvent>; 32], u64) {
        let events = *self
            .events
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        (events, self.dropped.load(Ordering::Relaxed))
    }
}

pub(super) struct ConsentTraceReport(pub(super) Arc<ConsentTrace>);

impl Drop for ConsentTraceReport {
    fn drop(&mut self) {
        let (events, dropped) = self.0.snapshot();
        // libtest retains this output on failure, including unwinding after
        // cleanup or an original assertion. No success is inferred from it.
        eprintln!("consent_trace capacity=32 dropped={dropped} events={events:?}");
    }
}

impl UdpTransport {
    pub(super) fn trace_consent(&self, nonce: ProbeNonce, stage: ConsentStage) {
        if let Some(trace) = &self.consent_trace {
            trace.record(nonce, stage);
        }
    }
}

#[test]
fn consent_trace_capacity_and_contention_report_missing_evidence_without_waiting() {
    let trace = ConsentTrace::new();
    {
        let _held = trace.events.lock().unwrap();
        trace.record([0; 8], ConsentStage::AckDecoded);
    }
    for index in 0..33 {
        trace.record([index; 8], ConsentStage::AckDecoded);
    }
    let (events, dropped) = trace.snapshot();
    assert_eq!(events.into_iter().flatten().count(), 32);
    assert_eq!(dropped, 2);
    assert_eq!(events[0].unwrap().nonce, [0; 8]);
    assert_eq!(events[31].unwrap().nonce, [31; 8]);
}
