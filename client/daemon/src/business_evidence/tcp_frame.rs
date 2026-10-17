//! Bounded recognition of the existing OS TCP tool's application bytes.
//! Byte coverage is historical input only: it mints no read/send/ACK authority.

use super::parser::{fold_sum, word_sum};
use super::{RegisteredFlow, RequestKind, MAX_TTL_SECS};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const HEADER_BYTES: usize = 63;
const MAX_FRAME_BYTES: usize = 1200;
const MAX_WIRE_BYTES: usize = 4 + MAX_FRAME_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TcpParseError {
    NotIpv4Tcp,
    Fragmented,
    Length,
    Checksum,
}

pub(crate) struct TcpSegment<'a> {
    flow: RegisteredFlow,
    sequence: u32,
    flags: u8,
    payload: &'a [u8],
}

pub(crate) fn parse_tcp_segment(raw: &[u8]) -> Result<TcpSegment<'_>, TcpParseError> {
    if raw.len() < 40 || raw[0] >> 4 != 4 || raw[9] != 6 {
        return Err(TcpParseError::NotIpv4Tcp);
    }
    let ihl = usize::from(raw[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
    if ihl < 20 || total != raw.len() || ihl + 20 > total {
        return Err(TcpParseError::Length);
    }
    if u16::from_be_bytes([raw[6], raw[7]]) & 0xbfff != 0 {
        return Err(TcpParseError::Fragmented);
    }
    let tcp = &raw[ihl..];
    let header = usize::from(tcp[12] >> 4) * 4;
    if header < 20 || header > tcp.len() {
        return Err(TcpParseError::Length);
    }
    if fold_sum(word_sum(&raw[..ihl])) != 0xffff
        || fold_sum(word_sum(&raw[12..20]) + 6 + tcp.len() as u32 + word_sum(tcp)) != 0xffff
    {
        return Err(TcpParseError::Checksum);
    }
    Ok(TcpSegment {
        flow: RegisteredFlow {
            src_v4: Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]),
            dst_v4: Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]),
            src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
            dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        },
        sequence: u32::from_be_bytes(tcp[4..8].try_into().unwrap()),
        flags: tcp[13],
        payload: &tcp[header..],
    })
}

impl TcpSegment<'_> {
    pub(crate) fn flow(&self) -> RegisteredFlow {
        self.flow
    }
    pub(crate) fn sequence(&self) -> u32 {
        self.sequence
    }
    pub(crate) fn is_syn(&self) -> bool {
        self.flags & 0x07 == 0x02 && self.payload.is_empty()
    }
    pub(crate) fn is_control_only(&self) -> bool {
        self.payload.is_empty() || self.flags & 0x06 != 0
    }
    pub(crate) fn overlaps_frame(&self, first: u32, wire_len: usize) -> bool {
        let offset = i64::from(self.sequence.wrapping_sub(first) as i32);
        offset < wire_len as i64 && offset + self.payload.len() as i64 > 0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpFrameKey {
    pub(crate) run: [u8; 16],
    pub(crate) round: [u8; 16],
    pub(crate) sequence: u32,
    pub(crate) request_nonce: [u8; 16],
    pub(crate) kind: RequestKind,
}

impl std::fmt::Debug for TcpFrameKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpFrameKey")
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("nonces", &"redacted")
            .finish()
    }
}

/// Immutable expected bytes, supplied by a separately registered tool plan.
/// Neither the flow nor this plan establishes a current connection identity.
pub(crate) struct TcpFramePlan {
    flow: RegisteredFlow,
    wire: [u8; MAX_WIRE_BYTES],
    wire_len: usize,
}

impl TcpFramePlan {
    pub(crate) fn new(flow: RegisteredFlow, key: TcpFrameKey, payload: u16) -> Option<Self> {
        let body_len = HEADER_BYTES + usize::from(payload);
        if !flow.valid() || body_len > MAX_FRAME_BYTES {
            return None;
        }
        let mut wire = [0; MAX_WIRE_BYTES];
        wire[..4].copy_from_slice(&(body_len as u32).to_be_bytes());
        let body = &mut wire[4..4 + body_len];
        body[..8].copy_from_slice(b"P2WTCE1\0");
        body[8] = match key.kind {
            RequestKind::Request => 0,
            RequestKind::Response => 1,
        };
        body[9..25].copy_from_slice(&key.run);
        body[25..41].copy_from_slice(&key.round);
        body[41..45].copy_from_slice(&key.sequence.to_be_bytes());
        body[45..61].copy_from_slice(&key.request_nonce);
        body[61..63].copy_from_slice(&payload.to_be_bytes());
        body[HEADER_BYTES..].fill(0xa5);
        Some(Self {
            flow,
            wire,
            wire_len: body_len + 4,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TcpCoverageResult {
    Added(usize),
    Retransmission,
    OutsideFrame,
    ControlOnly,
    FlowMismatch,
    BeforeCapture,
    Expired,
    Conflict,
    Invalidated,
}

/// Fixed per-frame bitmap; no stream buffer, retry, task or connection mirror.
pub(crate) struct TcpFrameCoverage {
    plan: TcpFramePlan,
    first_sequence: u32,
    started: Instant,
    deadline: Instant,
    seen: [u64; MAX_WIRE_BYTES.div_ceil(64)],
    covered: usize,
    conflicted: bool,
}

impl TcpFrameCoverage {
    pub(crate) fn new(
        plan: TcpFramePlan,
        first_sequence: u32,
        started: Instant,
        deadline: Instant,
    ) -> Option<Self> {
        let duration = deadline.checked_duration_since(started)?;
        if duration.is_zero() || duration > Duration::from_secs(MAX_TTL_SECS) {
            return None;
        }
        Some(Self {
            plan,
            first_sequence,
            started,
            deadline,
            seen: [0; MAX_WIRE_BYTES.div_ceil(64)],
            covered: 0,
            conflicted: false,
        })
    }

    pub(crate) fn observe(&mut self, segment: &TcpSegment<'_>, at: Instant) -> TcpCoverageResult {
        use TcpCoverageResult::*;
        if self.conflicted {
            return Invalidated;
        }
        if at < self.started {
            return BeforeCapture;
        }
        if at >= self.deadline {
            return Expired;
        }
        if segment.flow != self.plan.flow {
            return FlowMismatch;
        }
        // Pure ACK/FIN and SYN/RST packets cannot substitute application bytes.
        if segment.payload.is_empty() || segment.flags & 0x06 != 0 {
            return ControlOnly;
        }
        // An IPv4 segment and this frame are both far smaller than 2^31.
        // Signed relative sequence arithmetic also covers a frame wrapping 0.
        let offset = i64::from(segment.sequence.wrapping_sub(self.first_sequence) as i32);
        let start = offset.max(0) as usize;
        let end = (offset + segment.payload.len() as i64)
            .min(self.plan.wire_len as i64)
            .max(0) as usize;
        if start >= end {
            return OutsideFrame;
        }
        let source = (start as i64 - offset) as usize;
        if segment.payload[source..source + end - start] != self.plan.wire[start..end] {
            self.conflicted = true;
            return Conflict;
        }
        let before = self.covered;
        for index in start..end {
            let mask = 1 << (index % 64);
            if self.seen[index / 64] & mask == 0 {
                self.seen[index / 64] |= mask;
                self.covered += 1;
            }
        }
        if self.covered == before {
            Retransmission
        } else {
            Added(self.covered - before)
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        !self.conflicted && self.covered == self.plan.wire_len
    }
}

#[cfg(test)]
mod tests;
