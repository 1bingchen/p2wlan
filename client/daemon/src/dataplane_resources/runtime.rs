//! One explicit daemon observation lifetime and its bounded, read-only export.
//! Only diagnostics requests allocate/serialize readouts. Packet owners keep
//! the underlying fixed-size capture, never this runtime or any JSON value.
use super::{BufferStage, QueueStage, ResidencyStage, ResourceCapture, VecSite};
use serde_json::{json, Value};
use std::{sync::Arc, time::Instant};

pub(crate) struct RuntimeResourceCapture {
    capture: Arc<ResourceCapture>,
    started: Instant,
}

impl RuntimeResourceCapture {
    pub(crate) fn from_config(config: &crate::config::DiagnosticsConfig) -> Option<Arc<Self>> {
        (config.enabled && config.resource_capture).then(|| {
            Arc::new(Self {
                // Run-local random label, without node, network or payload data.
                capture: ResourceCapture::new(rand::random()),
                started: Instant::now(),
            })
        })
    }

    pub(crate) fn capture(&self) -> &Arc<ResourceCapture> {
        &self.capture
    }

    pub(crate) fn readout(&self) -> Value {
        let read_started_us = self.started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        let legacy = self.capture.snapshot();
        let residency = self.capture.residency_snapshot();
        let sites = VecSite::ALL.map(|site| {
            let counters = legacy.vec_site(site);
            json!({"site":site,"observed":counters.materialization_ops != 0,"counters":counters})
        });
        let queues = [QueueStage::ActorFifo, QueueStage::TaskOrUnjoinedFifo].map(|stage| {
            json!({"stage":stage,"scope_observed":legacy.fifo_scope_observed(stage),"counters":legacy.fifo(stage)})
        });
        let buffers = [
            BufferStage::ActiveOriginal,
            BufferStage::RetryPlaintext,
            BufferStage::PreparationPlaintext,
            BufferStage::SerializedWire,
            BufferStage::DataplaneAdmissionWait,
        ].map(|stage| {
            json!({"stage":stage,"scope_observed":legacy.buffer_scope_observed(stage),"counters":legacy.buffer(stage)})
        });
        const STAGES: [ResidencyStage; ResidencyStage::COUNT] = [
            ResidencyStage::ChannelReserve,
            ResidencyStage::RawChannel,
            ResidencyStage::DetachedRaw,
            ResidencyStage::PendingFifo,
            ResidencyStage::DiscardBatch,
            ResidencyStage::RetryPlaintext,
            ResidencyStage::PreparationPlaintext,
            ResidencyStage::SerializedWire,
            ResidencyStage::SessionBacklog,
            ResidencyStage::SessionFlush,
        ];
        let stages = STAGES.map(|stage| {
            json!({
                "stage":stage,
                "scope_observed":residency.coherent.then_some(residency.observed[stage as usize]),
                "totals":residency.stage(stage),
            })
        });
        let id = legacy
            .scope
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        json!({
            "schema_version":1,
            "enabled":legacy.enabled,
            "process_id":std::process::id(),
            "capture": {
                "id":id,"ended":legacy.ended,
                "read_started_us":read_started_us,
                "read_completed_us":self.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                "clock":"capture_monotonic",
                "site_and_lexical_counters": {
                    "coherent":legacy.coherent,"valid":legacy.valid,"gap_bits":legacy.gap_bits,
                    "read_span_us":legacy.read_completed.duration_since(legacy.read_started).as_micros().min(u64::MAX as u128) as u64,
                    "sites":sites,"queues":queues,"buffers":buffers,
                    "overlaps_observed_owner_residency":true,
                },
                "observed_owner_residency": {
                    "coherent":residency.coherent,"valid":residency.valid,
                    "gap_bits":residency.gap_bits,"unknown_bits":residency.unknown_bits,
                    "revision":residency.revision,"total":residency.total,
                    "capacity_high_water_bytes":residency.capacity_high_water_bytes,
                    "clone_ops":residency.clone_ops,"cloned_len_bytes":residency.cloned_len_bytes,
                    "stages":stages,
                    "whole_pipeline_bytes_measured":residency.whole_pipeline_bytes_measured,
                },
                "coverage": {
                    "allocator_alloc_calls_measured":legacy.allocator_alloc_calls_measured,
                    "allocator_free_calls_measured":legacy.allocator_free_calls_measured,
                    "kernel_bytes_measured":legacy.kernel_bytes_measured,
                    "queue_metadata_bytes_measured":legacy.queue_metadata_bytes_measured,
                    "crypto_temporaries_measured":legacy.crypto_temporaries_measured,
                    "whole_pipeline_bytes_measured":legacy.total_pipeline_bytes_measured,
                    "resident_set_bytes_measured":false,
                    "capacity_semantics":"observed_logical_vec_owner_lifetimes",
                    "excludes":["rx_ownership","control_buffers","relay_frames","crypto_temporaries","container_metadata","allocator_and_kernel"],
                },
            },
        })
    }
}

impl Drop for RuntimeResourceCapture {
    fn drop(&mut self) {
        // Existing message leases still drain after the run owner disappears.
        self.capture.finish();
    }
}
