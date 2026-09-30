/// Fixed-size encoding keeps the existing signaling session_id <=128 bytes
/// even when every generation is u64::MAX. Fields are opaque to old servers;
/// hh2 is sent only after explicit endpoint capability negotiation.
const HARD_HARD_V2_BYTES: usize = 90;

/// Zero denotes unavailable timing on the wire. The short-RPC clock rounds
/// submillisecond RTTs down to zero, while positive uncertainty identifies a
/// real sample. Preserve that evidence conservatively as one millisecond.
fn hard_hard_wire_timing(hint: Option<control::ControlTimingHint>) -> (u16, u16) {
    hint.filter(|hint| hint.uncertainty_ms > 0)
        .map_or((0, 0), |hint| {
            (
                hint.rtt_ms.clamp(1, u64::from(u16::MAX)) as u16,
                hint.uncertainty_ms.min(u64::from(u16::MAX)) as u16,
            )
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum HardHardV2Stage {
    Offer = 0,
    Answer = 1,
    Ready = 2,
    ReadyAck = 3,
    Sync = 4,
    SyncAck = 5,
}

impl HardHardV2Stage {
    fn is_barrier(self) -> bool {
        matches!(
            self,
            Self::Ready | Self::ReadyAck | Self::Sync | Self::SyncAck
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HardHardV2Envelope {
    pub(crate) stage: HardHardV2Stage,
    pub(crate) local: crate::peer::HardHardOfferParameters,
    pub(crate) remote: crate::peer::HardHardOfferParameters,
    pub(crate) phase: bool,
    pub(crate) strategy_order: u8,
    pub(crate) agreement: Option<crate::peer::HardHardAgreedPlan>,
    pub(crate) rtt_ms: u16,
    pub(crate) uncertainty_ms: u16,
}

const HARD_HARD_MODEL_NAMES: [&str; 10] = [
    "unknown",
    "stable",
    "fixed_step",
    "small_window",
    "high_entropy",
    "linear",
    "noisy_linear",
    "monotonic_window",
    "periodic",
    "unpredictable",
];

impl HardHardCoordination {
    fn encode_v2(&self, meta: &HardHardV2Envelope) -> Option<String> {
        use base64::Engine as _;
        let token = hex::decode(&self.token).ok()?;
        if token.len() != 16 || meta.strategy_order > 2 {
            return None;
        }
        let mut bytes = Vec::with_capacity(HARD_HARD_V2_BYTES);
        bytes.push(
            (meta.stage as u8 & 3)
                | ((meta.stage as u8 & 4) << 4)
                | u8::from(self.role == HardHardRole::Responder) << 2
                | u8::from(meta.phase) << 3
                | meta.strategy_order << 4,
        );
        bytes.extend_from_slice(&token);
        for value in [
            self.local_network_generation,
            self.remote_candidate_epoch,
            self.local_profile_generation,
            self.remote_profile_generation,
            self.remote_network_generation,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&[
            self.local_prediction_confidence,
            self.remote_prediction_confidence,
        ]);
        for name in [&self.local_prediction_model, &self.remote_prediction_model] {
            bytes.push(
                HARD_HARD_MODEL_NAMES
                    .iter()
                    .position(|known| *known == name)? as u8,
            );
        }
        for offer in [meta.local, meta.remote] {
            bytes.extend_from_slice(&[offer.socket_count, offer.prediction_count]);
            bytes.extend_from_slice(&offer.anchor_port.to_be_bytes());
        }
        bytes.push(meta.agreement.map_or(0, |plan| plan.strategy as u8));
        bytes.extend_from_slice(&meta.agreement.map_or([0; 16], |plan| plan.digest));
        bytes.extend_from_slice(&meta.rtt_ms.to_be_bytes());
        bytes.extend_from_slice(&meta.uncertainty_ms.to_be_bytes());
        if bytes.len() != HARD_HARD_V2_BYTES {
            return None;
        }
        Some(format!(
            "hh2:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        ))
    }

    fn parse_v2(value: &str) -> Option<Self> {
        use base64::Engine as _;
        let payload = value.strip_prefix("hh2:")?;
        if value.len() > 128 {
            return None;
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?;
        if bytes.len() != HARD_HARD_V2_BYTES || bytes[0] & 128 != 0 || ((bytes[0] >> 4) & 3) > 2 {
            return None;
        }
        let flags = bytes[0];
        let stage = match (flags & 3) | ((flags >> 4) & 4) {
            0 => HardHardV2Stage::Offer,
            1 => HardHardV2Stage::Answer,
            2 => HardHardV2Stage::Ready,
            3 => HardHardV2Stage::ReadyAck,
            4 => HardHardV2Stage::Sync,
            5 => HardHardV2Stage::SyncAck,
            _ => return None,
        };
        let role = if flags & 4 != 0 {
            HardHardRole::Responder
        } else {
            HardHardRole::Initiator
        };
        if (matches!(
            stage,
            HardHardV2Stage::Answer | HardHardV2Stage::ReadyAck | HardHardV2Stage::SyncAck
        )) != (role == HardHardRole::Responder)
        {
            return None;
        }
        let mut cursor = 17;
        let mut number = || {
            let result = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().ok()?);
            cursor += 8;
            Some(result)
        };
        let local_network_generation = number()?;
        let remote_candidate_epoch = number()?;
        let local_profile_generation = number()?;
        let remote_profile_generation = number()?;
        let remote_network_generation = number()?;
        let local_prediction_confidence = bytes[57];
        let remote_prediction_confidence = bytes[58];
        if local_prediction_confidence > 100 || remote_prediction_confidence > 100 {
            return None;
        }
        let local_prediction_model = HARD_HARD_MODEL_NAMES
            .get(usize::from(bytes[59]))?
            .to_string();
        let remote_prediction_model = HARD_HARD_MODEL_NAMES
            .get(usize::from(bytes[60]))?
            .to_string();
        let offer = |offset: usize| -> Option<crate::peer::HardHardOfferParameters> {
            let socket_count = bytes[offset];
            let prediction_count = bytes[offset + 1];
            if !matches!(socket_count, 0 | 2 | 4 | 8) || prediction_count > 32 {
                return None;
            }
            Some(crate::peer::HardHardOfferParameters {
                socket_count,
                prediction_count,
                anchor_port: u16::from_be_bytes(bytes[offset + 2..offset + 4].try_into().ok()?),
            })
        };
        let local = offer(61)?;
        let remote = offer(65)?;
        if local.socket_count == 0 || (stage != HardHardV2Stage::Offer && remote.socket_count == 0)
        {
            return None;
        }
        let digest: [u8; 16] = bytes[70..86].try_into().ok()?;
        let agreement = if stage == HardHardV2Stage::Offer {
            if bytes[69] != 0
                || digest != [0; 16]
                || remote != crate::peer::HardHardOfferParameters::default()
            {
                return None;
            }
            None
        } else {
            Some(crate::peer::HardHardAgreedPlan {
                strategy: crate::peer::HardHardProbeStrategy::from_wire(bytes[69])?,
                digest,
            })
        };
        Some(Self {
            role,
            token: hex::encode(&bytes[1..17]),
            local_network_generation,
            remote_candidate_epoch,
            local_profile_generation,
            remote_profile_generation,
            local_prediction_confidence,
            remote_prediction_confidence,
            local_prediction_model,
            remote_prediction_model,
            remote_network_generation,
            v2: Some(HardHardV2Envelope {
                stage,
                local,
                remote,
                phase: flags & 8 != 0,
                agreement,
                strategy_order: (flags >> 4) & 3,
                rtt_ms: u16::from_be_bytes(bytes[86..88].try_into().ok()?),
                uncertainty_ms: u16::from_be_bytes(bytes[88..90].try_into().ok()?),
            }),
        })
    }
}

/// Canonical transcript digest binds both full candidate sets, directional
/// generations, registrations, phase and the server-clock rendezvous time.
/// It is an agreement checksum; peer authentication comes from Control and
/// the token-scoped Probe key, not from an unkeyed digest.
fn hard_hard_plan_digest(
    offer: &HardHardCoordination,
    answer: &HardHardCoordination,
    offered: &[SocketAddr],
    answered: &[SocketAddr],
    registrations: (u64, u64),
    server_deadline: u64,
    strategy: crate::peer::HardHardProbeStrategy,
) -> Option<[u8; 16]> {
    use sha2::Digest as _;
    let offer_meta = offer.v2.as_ref()?;
    let answer_meta = answer.v2.as_ref()?;
    if offer_meta.stage != HardHardV2Stage::Offer
        || answer_meta.stage != HardHardV2Stage::Answer
        || offer.role != HardHardRole::Initiator
        || answer.role != HardHardRole::Responder
        || strategy
            != crate::peer::HardHardProbeStrategy::select_with_order(
                offer_meta.local,
                answer_meta.local,
                offer_meta.strategy_order,
            )
        || offer_meta.strategy_order != answer_meta.strategy_order
        || offer.token != answer.token
        || offer_meta.phase != answer_meta.phase
        || answer_meta.remote != offer_meta.local
        || !offer_meta.local.is_valid(offered)
        || !answer_meta.local.is_valid(answered)
        || registrations.0 == 0
        || registrations.1 == 0
        || server_deadline == 0
    {
        return None;
    }
    let mut hash = sha2::Sha256::new();
    hash.update(b"p2wlan/hh2/plan/v1\0");
    hash.update(registrations.0.to_be_bytes());
    hash.update(registrations.1.to_be_bytes());
    hash.update(server_deadline.to_be_bytes());
    hash.update([strategy as u8]);
    for (envelope, candidates) in [(offer, offered), (answer, answered)] {
        let mut normalized = envelope.clone();
        normalized.v2.as_mut()?.agreement = None;
        let encoded = normalized.encode_v2(normalized.v2.as_ref()?)?;
        hash.update((encoded.len() as u16).to_be_bytes());
        hash.update(encoded.as_bytes());
        hash.update((candidates.len() as u16).to_be_bytes());
        for endpoint in candidates {
            let value = endpoint.to_string();
            hash.update((value.len() as u16).to_be_bytes());
            hash.update(value.as_bytes());
        }
    }
    let digest = hash.finalize();
    digest[..16].try_into().ok()
}
