//! Test-only receive boundary for loopback NAT fixtures. The source endpoints
//! are fixed once by one harness; readers share the same transport-owned gate.

use super::*;
use std::sync::OnceLock;

#[derive(Default)]
pub(crate) struct TestUdpIngressGate {
    allowed_sources: OnceLock<HashSet<SocketAddr>>,
    rejected_datagrams: AtomicU64,
}

impl TestUdpIngressGate {
    pub(crate) fn allow_sources_once(&self, sources: impl IntoIterator<Item = SocketAddr>) {
        let sources: HashSet<_> = sources.into_iter().collect();
        assert!(!sources.is_empty() && sources.len() <= 16);
        assert!(self.allowed_sources.set(sources).is_ok());
    }

    pub(super) fn admit(&self, source: SocketAddr) -> bool {
        if self
            .allowed_sources
            .get()
            .is_some_and(|sources| sources.contains(&source))
        {
            true
        } else {
            self.rejected_datagrams.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    pub(crate) fn rejected_datagrams(&self) -> u64 {
        self.rejected_datagrams.load(Ordering::Relaxed)
    }
}

impl UdpTransport {
    pub(crate) fn with_test_ingress_gate(mut self, gate: Arc<TestUdpIngressGate>) -> Self {
        assert!(self.test_ingress_gate.is_none());
        self.test_ingress_gate = Some(gate);
        self
    }
}
