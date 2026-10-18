//! Interleave only pending original Full metadata with the same control read.
use super::{read_line, CaptureFailure, CaptureSession};
use std::sync::Arc;

pub(super) async fn next_line(
    stream: &mut tokio::net::UnixStream,
    pending: &mut Vec<u8>,
    input_bytes: &mut usize,
    end: tokio::time::Instant,
    session: &Arc<CaptureSession>,
) -> Result<Option<Vec<u8>>, CaptureFailure> {
    let read = read_line(stream, pending, input_bytes, end);
    #[cfg(any(target_os = "linux", all(unix, test)))]
    {
        tokio::pin!(read);
        loop {
            if tokio::time::Instant::now() >= end {
                return Err(CaptureFailure::ControlNotReady);
            }
            tokio::select! {
                // Process the real producer's bounded notification before
                // another buffered command. Repeated snapshots cannot starve
                // it; notifications never rebuild this read future or change
                // its absolute end, partial input or byte budget.
                biased;
                _ = session.full_completion_ready() => session.complete_pending_fulls(),
                result = &mut read => return result,
                _ = session.full_metadata_released(), if session.full_completion_pending() => {
                    session.complete_pending_fulls();
                }
            }
        }
    }
    #[cfg(not(any(target_os = "linux", all(unix, test))))]
    {
        let _ = session;
        read.await
    }
}
