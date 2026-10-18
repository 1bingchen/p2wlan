#[cfg(any(target_os = "linux", test))]
use crate::business_evidence::RequestKind;
use crate::business_evidence::{OsUdpReqKey, RegisteredFlow};
use serde::Deserialize;
#[cfg(any(target_os = "linux", test))]
use std::net::Ipv4Addr;

#[cfg(any(unix, test))]
pub(super) const MAX_PLAN_BYTES: usize = 128 * 1024;
#[cfg(any(target_os = "linux", test))]
pub(super) const MAX_REQUESTS: usize = crate::business_evidence::MAX_REQUESTS;
#[cfg(any(target_os = "linux", test))]
pub(super) const MAX_PEER_BYTES: usize = crate::business_evidence::MAX_PEER_ID_BYTES;
pub(super) const MAX_BINDINGS_PER_PACKET: usize = 8;
#[cfg(any(target_os = "linux", all(unix, test)))]
pub(super) const CAPTURE_TTL_SECS: u64 = crate::business_evidence::MAX_TTL_SECS;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub(super) enum Protocol {
    Udp,
    Tcp,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub(super) enum Kind {
    Request,
    Response,
}

#[cfg(any(target_os = "linux", test))]
impl From<Kind> for RequestKind {
    fn from(value: Kind) -> Self {
        match value {
            Kind::Request => Self::Request,
            Kind::Response => Self::Response,
        }
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WirePlan {
    schema_version: u8,
    capture_id: String,
    producer_scope: String,
    flows: Vec<WireFlow>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFlow {
    protocol: Protocol,
    kind: Kind,
    peer_id: String,
    run_nonce: String,
    round_nonce: String,
    bind_ip: Ipv4Addr,
    bind_port: u16,
    target_ip: Ipv4Addr,
    target_port: u16,
    payload_bytes: u16,
    request_nonces: Vec<String>,
}

pub(super) struct RegisteredFlowPlan {
    pub(super) protocol: Protocol,
    pub(super) peer: String,
    pub(super) flow: RegisteredFlow,
    pub(super) payload_bytes: u16,
    pub(super) requests: Vec<OsUdpReqKey>,
}

#[cfg(any(target_os = "linux", test))]
pub(super) struct RegistrationPlan {
    pub(super) capture_id: [u8; 16],
    pub(super) producer_scope: [u8; 16],
    pub(super) flows: Vec<RegisteredFlowPlan>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaptureFailure {
    Capacity,
    InvalidPlan,
    InvalidDescriptor,
    #[cfg(not(target_os = "linux"))]
    UnsupportedPlatform,
    #[cfg(unix)]
    ControlNotReady,
    #[cfg(unix)]
    ControlProtocol,
    Contended,
    CounterExhausted,
    ForeignDevice,
    FrameConflict,
    MissingTcpOpen,
    DuplicateWrite,
    OriginalIngressSource,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    RegistrationConflict,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    Expired,
}

impl std::fmt::Display for CaptureFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CaptureFailure {}

#[cfg(any(target_os = "linux", test))]
pub(super) fn nonce(raw: &str) -> Result<[u8; 16], CaptureFailure> {
    if raw.len() != 32
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CaptureFailure::InvalidPlan);
    }
    let mut result = [0; 16];
    hex::decode_to_slice(raw, &mut result).map_err(|_| CaptureFailure::InvalidPlan)?;
    Ok(result)
}

#[cfg(any(target_os = "linux", test))]
impl RegistrationPlan {
    #[cfg(test)]
    pub(super) fn decode(raw: &[u8]) -> Result<Self, CaptureFailure> {
        Self::decode_inner(raw, false)
    }

    /// The owned control connection can open before the daemon knows its VIP.
    /// Empty labels create no request, read or connection-owner authority.
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn decode_open(raw: &[u8]) -> Result<Self, CaptureFailure> {
        Self::decode_inner(raw, true)
    }

    fn decode_inner(raw: &[u8], allow_empty: bool) -> Result<Self, CaptureFailure> {
        if raw.is_empty() || raw.len() > MAX_PLAN_BYTES {
            return Err(CaptureFailure::Capacity);
        }
        let wire: WirePlan =
            serde_json::from_slice(raw).map_err(|_| CaptureFailure::InvalidPlan)?;
        Self::validate(wire, allow_empty)
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn from_registration(wire: WirePlan) -> Result<Self, CaptureFailure> {
        Self::validate(wire, false)
    }

    fn validate(wire: WirePlan, allow_empty: bool) -> Result<Self, CaptureFailure> {
        if wire.schema_version != 1
            || (!allow_empty && wire.flows.is_empty())
            || wire.flows.len() > MAX_REQUESTS
        {
            return Err(CaptureFailure::InvalidPlan);
        }
        let capture_id = nonce(&wire.capture_id)?;
        let producer_scope = nonce(&wire.producer_scope)?;
        let mut flows = Vec::with_capacity(wire.flows.len());
        let mut total = 0usize;
        // An ambiguous flow/sequence cannot choose a different registration
        // after a read. Labels are immutable for this one descriptor scope.
        let mut all_keys = std::collections::BTreeSet::new();
        for flow in wire.flows {
            total = total
                .checked_add(flow.request_nonces.len())
                .filter(|total| *total <= MAX_REQUESTS)
                .ok_or(CaptureFailure::Capacity)?;
            if flow.request_nonces.is_empty()
                || flow.peer_id.is_empty()
                || flow.peer_id.len() > MAX_PEER_BYTES
                || flow.peer_id.chars().any(char::is_control)
                || flow.bind_port == 0
                || flow.target_port == 0
                || [flow.bind_ip, flow.target_ip]
                    .into_iter()
                    .any(|ip| ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast())
                || flow.payload_bytes == 0
                || 63usize + usize::from(flow.payload_bytes) > 1200
            {
                return Err(CaptureFailure::InvalidPlan);
            }
            let registered = RegisteredFlow {
                src_v4: flow.bind_ip,
                dst_v4: flow.target_ip,
                src_port: flow.bind_port,
                dst_port: flow.target_port,
            };
            if flows.iter().any(|old: &RegisteredFlowPlan| {
                old.flow == registered && old.protocol == flow.protocol
            }) {
                return Err(CaptureFailure::InvalidPlan);
            }
            let run = nonce(&flow.run_nonce)?;
            let round = nonce(&flow.round_nonce)?;
            let mut requests = Vec::with_capacity(flow.request_nonces.len());
            let mut unique_nonces = std::collections::BTreeSet::new();
            for (index, request) in flow.request_nonces.into_iter().enumerate() {
                let key = OsUdpReqKey {
                    run,
                    round,
                    sequence: u32::try_from(index).map_err(|_| CaptureFailure::Capacity)?,
                    request_nonce: nonce(&request)?,
                    kind: flow.kind.into(),
                };
                if !unique_nonces.insert(key.request_nonce)
                    || !all_keys.insert((flow.protocol, key))
                {
                    return Err(CaptureFailure::InvalidPlan);
                }
                requests.push(key);
            }
            flows.push(RegisteredFlowPlan {
                protocol: flow.protocol,
                peer: flow.peer_id,
                flow: registered,
                payload_bytes: flow.payload_bytes,
                requests,
            });
        }
        Ok(Self {
            capture_id,
            producer_scope,
            flows,
        })
    }
}
