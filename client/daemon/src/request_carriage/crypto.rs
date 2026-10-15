//! Carriage adapters around the single original crypto core in each path.
use super::{DeliveryMetadata, EncryptedRequestDelivery, RawRequestDelivery};
use crate::error::{DaemonError, Result};
use crate::transport::{
    SessionBoundEncryptionWithSource, SessionUnavailableReason, WireGuardTransport,
};

fn observe_crypto_input(transport: &WireGuardTransport, packet: &mut RawRequestDelivery) {
    packet
        .metadata
        .observe_crypto_input(transport.resource_capture(), &packet.raw.packet);
}

pub(crate) enum RequestEncryptionAttempt {
    Encrypted {
        packet: EncryptedRequestDelivery,
        plaintext: RawRequestDelivery,
        session_lock_wait_us: u64,
        crypto_us: u64,
    },
    Contended(RawRequestDelivery),
    Unavailable {
        packet: RawRequestDelivery,
        reason: SessionUnavailableReason,
    },
    Failed {
        packet: RawRequestDelivery,
        error: DaemonError,
    },
}

impl WireGuardTransport {
    pub(crate) async fn encrypt_request_with_emit_guard(
        &self,
        mut packet: RawRequestDelivery,
    ) -> Result<Option<EncryptedRequestDelivery>> {
        observe_crypto_input(self, &mut packet);
        let RawRequestDelivery { raw, metadata } = packet;
        let (binding, original_residency) = metadata.into_parts();
        let encrypted = if binding.is_some() {
            self.encrypt_outbound_with_emit_guard_and_source(raw)
                .await?
        } else {
            self.encrypt_outbound_with_emit_guard_observed(raw).await?
        };
        // The original input observation survives the original crypto future,
        // including cancellation, but does not retain or clone its Vec.
        drop(original_residency);
        Ok(encrypted.map(|encrypted| {
            let (packet, source, residency) = encrypted.into_observed_parts();
            EncryptedRequestDelivery {
                packet,
                metadata: DeliveryMetadata::from_parts(binding, residency),
                source,
                echo_emit: None,
            }
        }))
    }

    pub(crate) fn try_encrypt_request_with_emit_guard_for_session(
        &self,
        mut packet: RawRequestDelivery,
        expected_session_instance: u64,
    ) -> RequestEncryptionAttempt {
        observe_crypto_input(self, &mut packet);
        let RawRequestDelivery { raw, metadata } = packet;
        let (binding, original_residency) = metadata.into_parts();
        let encrypted = if binding.is_some() {
            self.try_encrypt_outbound_with_emit_guard_for_session_and_source(
                raw,
                expected_session_instance,
            )
        } else {
            self.try_encrypt_outbound_with_emit_guard_for_session(raw, expected_session_instance)
        };
        match encrypted {
            SessionBoundEncryptionWithSource::Encrypted {
                packet,
                plaintext,
                session_lock_wait_us,
                crypto_us,
            } => {
                let (packet, source, residency) = packet.into_observed_parts();
                RequestEncryptionAttempt::Encrypted {
                    packet: EncryptedRequestDelivery {
                        packet,
                        metadata: DeliveryMetadata::from_parts(binding.clone(), residency),
                        source,
                        echo_emit: None,
                    },
                    plaintext: RawRequestDelivery {
                        raw: plaintext,
                        metadata: DeliveryMetadata::from_parts(binding, original_residency),
                    },
                    session_lock_wait_us,
                    crypto_us,
                }
            }
            SessionBoundEncryptionWithSource::Contended(raw) => {
                RequestEncryptionAttempt::Contended(RawRequestDelivery {
                    raw,
                    metadata: DeliveryMetadata::from_parts(binding, original_residency),
                })
            }
            SessionBoundEncryptionWithSource::Unavailable {
                packet: raw,
                reason,
            } => RequestEncryptionAttempt::Unavailable {
                packet: RawRequestDelivery {
                    raw,
                    metadata: DeliveryMetadata::from_parts(binding, original_residency),
                },
                reason,
            },
            SessionBoundEncryptionWithSource::Failed { packet: raw, error } => {
                RequestEncryptionAttempt::Failed {
                    packet: RawRequestDelivery {
                        raw,
                        metadata: DeliveryMetadata::from_parts(binding, original_residency),
                    },
                    error,
                }
            }
        }
    }
}
