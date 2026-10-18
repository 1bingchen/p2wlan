//! Optional immutable provenance in the existing one-pointer inbound field.
use crate::business_evidence::AuthenticatedIngressContext;
use crate::os_request_capture::KernelIngressBinding;
use std::sync::Arc;

pub(crate) struct PacketIngressEvidence {
    legacy: Option<Arc<AuthenticatedIngressContext>>,
    kernel: Option<Arc<KernelIngressBinding>>,
}

impl PacketIngressEvidence {
    pub(crate) fn from_parts(
        legacy: Option<Arc<AuthenticatedIngressContext>>,
        kernel: Option<Arc<KernelIngressBinding>>,
    ) -> Option<Arc<Self>> {
        (legacy.is_some() || kernel.is_some()).then(|| Arc::new(Self { legacy, kernel }))
    }

    pub(crate) fn legacy(&self) -> Option<&Arc<AuthenticatedIngressContext>> {
        self.legacy.as_ref()
    }

    pub(crate) fn kernel(&self) -> Option<&Arc<KernelIngressBinding>> {
        self.kernel.as_ref()
    }
}

impl std::fmt::Debug for PacketIngressEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketIngressEvidence")
            .field("legacy_present", &self.legacy.is_some())
            .field("sealed_kernel_ingress_present", &self.kernel.is_some())
            .finish()
    }
}

impl PartialEq for PacketIngressEvidence {
    fn eq(&self, other: &Self) -> bool {
        self.legacy == other.legacy
            && match (&self.kernel, &other.kernel) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}
impl Eq for PacketIngressEvidence {}
