//! Read-only identity of this actual process and Linux monotonic clock.
//! Received PIDs, JSON labels and remote timestamps never create this value.
#[cfg(unix)]
use serde::Serialize;

#[cfg(unix)]
#[derive(Clone, Serialize)]
pub(super) struct NativeClockScope {
    clock_name: &'static str,
    boot_id: String,
    process_id: u32,
    parent_pid: u32,
    uid: u32,
    start_ticks: u64,
    net_namespace: String,
}

#[cfg(unix)]
impl NativeClockScope {
    #[cfg(target_os = "linux")]
    pub(super) fn capture() -> Option<Self> {
        use std::io::Read;
        fn bounded(path: &str) -> Option<String> {
            let mut raw = String::new();
            std::fs::File::open(path)
                .ok()?
                .take(4097)
                .read_to_string(&mut raw)
                .ok()?;
            (raw.len() <= 4096).then(|| raw.trim().to_owned())
        }
        let boot_id = bounded("/proc/sys/kernel/random/boot_id")?;
        if boot_id.len() != 36
            || !boot_id.bytes().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
        {
            return None;
        }
        let process_id = std::process::id();
        let stat = bounded("/proc/self/stat")?;
        if stat.split_once('(')?.0.trim().parse::<u32>().ok()? != process_id {
            return None;
        }
        let tail: Vec<_> = stat.rsplit_once(')')?.1.split_whitespace().collect();
        let parent_pid = tail.get(1)?.parse::<u32>().ok()?;
        let start_ticks = tail.get(19)?.parse::<u64>().ok()?;
        let namespace = std::fs::read_link("/proc/self/ns/net").ok()?;
        let net_namespace = namespace.to_str()?.to_owned();
        if !net_namespace.starts_with("net:[")
            || !net_namespace.ends_with(']')
            || net_namespace.len() > 64
        {
            return None;
        }
        monotonic_ns()?;
        Some(Self {
            clock_name: "CLOCK_MONOTONIC",
            boot_id,
            process_id,
            parent_pid,
            uid: unsafe { libc::geteuid() },
            start_ticks,
            net_namespace,
        })
    }

    #[cfg(all(unix, test, not(target_os = "linux")))]
    pub(super) fn capture() -> Option<Self> {
        None
    }
}

#[cfg(target_os = "linux")]
pub(super) fn monotonic_ns() -> Option<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return None;
    }
    u64::try_from(value.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(value.tv_nsec).ok()?)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn monotonic_ns() -> Option<u64> {
    None
}
