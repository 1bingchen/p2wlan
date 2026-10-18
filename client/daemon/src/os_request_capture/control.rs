use super::plan::CaptureFailure;
#[cfg(unix)]
use super::plan::MAX_PLAN_BYTES;
#[cfg(any(target_os = "linux", all(unix, test)))]
use super::plan::{RegistrationPlan, WirePlan};
use super::registry::CaptureSession;
use crate::peer::PeerManager;
#[cfg(unix)]
use serde::Deserialize;
use std::sync::Arc;

const FD_ENV: &str = "P2WLAN_OS_REQUEST_CONTROL_FD";
const SOCKET_ENV: &str = "P2WLAN_OS_REQUEST_CONTROL_SOCKET";
#[cfg(unix)]
mod deadline;

/// Select envelope capacity before constructing the original transport.
/// Presence alone grants no capture authority; setup still validates the
/// platform, descriptor, peer and registration before any worker starts.
pub(crate) fn requested_from_env() -> bool {
    std::env::var_os(FD_ENV).is_some() || std::env::var_os(SOCKET_ENV).is_some()
}
#[cfg(unix)]
const MAX_CONTROL_BYTES: usize = 4 * 1024 * 1024;
#[cfg(unix)]
const MAX_CONTROL_RECORDS: usize = 8192;

pub(crate) struct CaptureSetup {
    pub(crate) session: Arc<CaptureSession>,
    pub(crate) channel: ControlChannel,
}

#[cfg(unix)]
pub(crate) struct ControlChannel {
    stream: tokio::net::UnixStream,
    pending: Vec<u8>,
    input_bytes: usize,
    output_bytes: usize,
    records: usize,
    session: Arc<CaptureSession>,
}
#[cfg(not(unix))]
pub(crate) struct ControlChannel;

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Snapshot {
        original_deadline_ns: Option<u64>,
    },
    Close {},
    #[cfg(any(target_os = "linux", all(unix, test)))]
    Register {
        plan: WirePlan,
        original_deadline_ns: Option<u64>,
    },
    #[cfg(any(target_os = "linux", all(unix, test)))]
    ObserveOriginalWriteWindow {
        window: super::registry::write_window::WireWriteWindow,
    },
}

impl CaptureSetup {
    pub(crate) async fn from_env(peers: &Arc<PeerManager>) -> Result<Option<Self>, CaptureFailure> {
        let inherited = std::env::var_os(FD_ENV);
        let socket = std::env::var_os(SOCKET_ENV);
        if inherited.is_some() && socket.is_some() {
            return Err(CaptureFailure::InvalidDescriptor);
        }
        if let Some(path) = socket {
            #[cfg(target_os = "linux")]
            {
                return Self::from_socket_path(std::path::Path::new(&path), peers)
                    .await
                    .map(Some);
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (path, peers);
                return Err(CaptureFailure::UnsupportedPlatform);
            }
        }
        let Some(raw) = inherited else {
            return Ok(None);
        };
        let value = raw.to_str().ok_or(CaptureFailure::InvalidDescriptor)?;
        if value.is_empty() || value.len() > 10 || !value.bytes().all(|c| c.is_ascii_digit()) {
            return Err(CaptureFailure::InvalidDescriptor);
        }
        let fd: i32 = value
            .parse()
            .map_err(|_| CaptureFailure::InvalidDescriptor)?;
        if fd < 3 {
            return Err(CaptureFailure::InvalidDescriptor);
        }
        #[cfg(target_os = "linux")]
        {
            Self::from_inherited_fd(fd, peers).await.map(Some)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (fd, peers);
            Err(CaptureFailure::UnsupportedPlatform)
        }
    }

    /// A fresh owned connection avoids lending any extra inherited descriptor
    /// to the original daemon/probe process groups.
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) async fn from_socket_path(
        path: &std::path::Path,
        peers: &Arc<PeerManager>,
    ) -> Result<Self, CaptureFailure> {
        let end = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        if !path.is_absolute() || path.as_os_str().as_encoded_bytes().len() > 100 {
            return Err(CaptureFailure::InvalidDescriptor);
        }
        let stream = tokio::time::timeout_at(end, tokio::net::UnixStream::connect(path))
            .await
            .map_err(|_| CaptureFailure::ControlNotReady)?
            .map_err(|_| CaptureFailure::InvalidDescriptor)?;
        Self::from_stream(stream, peers, end).await
    }

    /// A received integer can name a descriptor; it cannot transfer Rust
    /// ownership. This path owns only a new duplicate and never closes or
    /// changes the caller's original descriptor, on success or failure.
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) async fn from_inherited_fd(
        fd: std::os::fd::RawFd,
        peers: &Arc<PeerManager>,
    ) -> Result<Self, CaptureFailure> {
        let copy = duplicate_descriptor(fd)?;
        Self::from_owned_descriptor(copy, peers).await
    }

    /// Explicit ownership transfer for a launcher that already owns its socket.
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) async fn from_owned_descriptor(
        descriptor: std::os::fd::OwnedFd,
        peers: &Arc<PeerManager>,
    ) -> Result<Self, CaptureFailure> {
        use std::os::fd::AsFd;
        validate_connected_unix(descriptor.as_fd())?;
        let std_stream = std::os::unix::net::UnixStream::from(descriptor);
        let stream = tokio::net::UnixStream::from_std(std_stream)
            .map_err(|_| CaptureFailure::InvalidDescriptor)?;
        let end = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        Self::from_stream(stream, peers, end).await
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    async fn from_stream(
        mut stream: tokio::net::UnixStream,
        peers: &Arc<PeerManager>,
        initial_end: tokio::time::Instant,
    ) -> Result<Self, CaptureFailure> {
        let credentials = stream
            .peer_cred()
            .map_err(|_| CaptureFailure::InvalidDescriptor)?;
        if credentials.uid() != unsafe { libc::geteuid() } {
            return Err(CaptureFailure::InvalidDescriptor);
        }
        let mut pending = Vec::new();
        // One fixed metadata-start deadline, not a refill per partial read.
        // This opt-in preparation never starts/restarts an OS probe clock.
        let mut input_bytes = 0;
        let raw = read_line(&mut stream, &mut pending, &mut input_bytes, initial_end)
            .await?
            .ok_or(CaptureFailure::ControlNotReady)?;
        let plan = RegistrationPlan::decode_open(&raw)?;
        let session = CaptureSession::from_control_descriptor(plan, peers)?;
        let channel = ControlChannel {
            stream,
            pending,
            input_bytes,
            output_bytes: 0,
            records: 1,
            session: session.clone(),
        };
        Ok(Self { session, channel })
    }
}

#[cfg(any(target_os = "linux", all(unix, test)))]
fn duplicate_descriptor(fd: std::os::fd::RawFd) -> Result<std::os::fd::OwnedFd, CaptureFailure> {
    use std::os::fd::{FromRawFd, OwnedFd};
    // Validate the owned copy, not a potentially reused original integer.
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(CaptureFailure::InvalidDescriptor);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

#[cfg(any(target_os = "linux", all(unix, test)))]
fn validate_connected_unix(descriptor: std::os::fd::BorrowedFd<'_>) -> Result<(), CaptureFailure> {
    use std::os::fd::AsRawFd;
    let fd = descriptor.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_NONBLOCK == 0 {
        return Err(CaptureFailure::InvalidDescriptor);
    }
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    if unsafe {
        libc::getpeername(
            fd,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    } != 0
        || i32::from(address.ss_family) != libc::AF_UNIX
    {
        return Err(CaptureFailure::InvalidDescriptor);
    }
    let mut kind = 0i32;
    let mut kind_len = std::mem::size_of_val(&kind) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut i32).cast(),
            &mut kind_len,
        )
    } != 0
        || kind != libc::SOCK_STREAM
    {
        return Err(CaptureFailure::InvalidDescriptor);
    }
    Ok(())
}

#[cfg(unix)]
async fn read_line(
    stream: &mut tokio::net::UnixStream,
    pending: &mut Vec<u8>,
    input_bytes: &mut usize,
    end: tokio::time::Instant,
) -> Result<Option<Vec<u8>>, CaptureFailure> {
    use tokio::io::AsyncReadExt;
    loop {
        if let Some(index) = pending.iter().position(|byte| *byte == b'\n') {
            let rest = pending.split_off(index + 1);
            let mut line = std::mem::replace(pending, rest);
            line.pop();
            return Ok(Some(line));
        }
        let available = MAX_PLAN_BYTES.saturating_sub(pending.len());
        if available == 0 {
            return Err(CaptureFailure::Capacity);
        }
        let mut buf = [0u8; 4096];
        let capacity = available.min(buf.len());
        let n = tokio::time::timeout_at(end, stream.read(&mut buf[..capacity]))
            .await
            .map_err(|_| CaptureFailure::ControlNotReady)?
            .map_err(|_| CaptureFailure::ControlProtocol)?;
        if n == 0 {
            return if pending.is_empty() {
                Ok(None)
            } else {
                Err(CaptureFailure::ControlProtocol)
            };
        }
        *input_bytes = input_bytes
            .checked_add(n)
            .filter(|value| *value <= MAX_CONTROL_BYTES)
            .ok_or(CaptureFailure::Capacity)?;
        pending.extend_from_slice(&buf[..n]);
    }
}

#[cfg(unix)]
impl ControlChannel {
    pub(crate) async fn run(mut self) -> Result<(), CaptureFailure> {
        loop {
            let end = tokio::time::Instant::from_std(self.session.expires());
            if tokio::time::Instant::now() >= end {
                return Ok(());
            }
            let line = match read_line(
                &mut self.stream,
                &mut self.pending,
                &mut self.input_bytes,
                end,
            )
            .await
            {
                Err(CaptureFailure::ControlNotReady) if tokio::time::Instant::now() >= end => {
                    return Ok(())
                }
                result => result?,
            };
            let Some(line) = line else { return Ok(()) };
            self.records = self
                .records
                .checked_add(1)
                .ok_or(CaptureFailure::Capacity)?;
            if self.records > MAX_CONTROL_RECORDS || line.len() > MAX_PLAN_BYTES {
                return Err(CaptureFailure::Capacity);
            }
            let (encoded, reply_end) = match serde_json::from_slice::<Command>(&line)
                .map_err(|_| CaptureFailure::ControlProtocol)?
            {
                Command::Close {} => return Ok(()),
                Command::Snapshot {
                    original_deadline_ns,
                } => {
                    let (value, reply_end) = match original_deadline_ns {
                        Some(ns) => {
                            let end = self.session.metadata_command_deadline(ns)?;
                            (self.session.snapshot_control(end).await?, end)
                        }
                        None => (self.session.snapshot()?, end),
                    };
                    (serde_json::to_vec(&value), reply_end)
                }
                #[cfg(any(target_os = "linux", all(unix, test)))]
                Command::Register {
                    plan,
                    original_deadline_ns,
                } => {
                    let plan = RegistrationPlan::from_registration(plan)?;
                    let (value, reply_end) = match original_deadline_ns {
                        Some(ns) => {
                            let end = self.session.metadata_command_deadline(ns)?;
                            (self.session.register_control(plan, end).await?, end)
                        }
                        None => (self.session.register(plan)?, end),
                    };
                    (serde_json::to_vec(&value), reply_end)
                }
                #[cfg(any(target_os = "linux", all(unix, test)))]
                Command::ObserveOriginalWriteWindow { window } => {
                    self.session.observe_original_write_window(window).await?;
                    continue;
                }
            };
            let encoded = encoded.map_err(|_| CaptureFailure::ControlProtocol)?;
            self.reply(encoded, reply_end).await?;
        }
    }

    async fn reply(
        &mut self,
        mut encoded: Vec<u8>,
        end: tokio::time::Instant,
    ) -> Result<(), CaptureFailure> {
        use tokio::io::AsyncWriteExt;
        encoded.push(b'\n');
        self.output_bytes = self
            .output_bytes
            .checked_add(encoded.len())
            .filter(|value| *value <= MAX_CONTROL_BYTES)
            .ok_or(CaptureFailure::Capacity)?;
        tokio::time::timeout_at(end, self.stream.write_all(&encoded))
            .await
            .map_err(|_| CaptureFailure::ControlNotReady)?
            .map_err(|_| CaptureFailure::ControlProtocol)
    }
}
#[cfg(not(unix))]
impl ControlChannel {
    pub(crate) async fn run(self) -> Result<(), CaptureFailure> {
        Err(CaptureFailure::UnsupportedPlatform)
    }
}
#[cfg(unix)]
impl Drop for ControlChannel {
    fn drop(&mut self) {
        self.session.retire();
    }
}
