use super::*;

pub(crate) const HARD_HARD_BIRTHDAY_WAVE_INTERVAL: Duration = Duration::from_millis(20);

pub(crate) const HARD_HARD_BIRTHDAY_WAVES: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum HardHardWindowStrategy {
    Scatter,
    FixedAnchor,
}

/// Generate a bounded, token-scoped birthday window. It deliberately uses a
/// permutation stride over the UDP port ring and stops at the negotiated
/// level; it never enumerates the full 65,535-port space.
pub(crate) fn hard_hard_birthday_candidates(
    public_ip: IpAddr,
    observed_ports: &[u16],
    level: usize,
    session_token: &str,
) -> Vec<SocketAddr> {
    // The wire level is bounded independently of caller input. In particular,
    // zero must not fall through the observed-port loop and grow a window.
    let level = level.min(256);
    if level == 0 {
        return Vec::new();
    }
    let mut seed = 0xcbf29ce484222325u64;
    for byte in public_ip.to_string().bytes().chain(session_token.bytes()) {
        seed ^= u64::from(byte);
        seed = seed.wrapping_mul(0x100000001b3);
    }
    // 65535 = 3 * 5 * 17 * 257: odd is not sufficient for a permutation.
    // A coprime stride visits every nonzero port once before repeating.
    let modulus = u64::from(u16::MAX);
    let stride = birthday_permutation_stride(seed);
    let mut candidates = Vec::with_capacity(level);
    let mut seen = HashSet::new();
    for port in observed_ports.iter().take(256) {
        if *port != 0 && seen.insert(*port) {
            candidates.push(SocketAddr::new(public_ip, *port));
            if candidates.len() == level {
                return candidates;
            }
        }
    }
    let origin = seed % modulus;
    // At most `seen.len()` permutation entries can duplicate observed ports;
    // these many visits therefore fill the window, without a full-ring scan.
    for index in 0..level + seen.len() {
        let port = ((origin + (index as u64).saturating_mul(stride)) % modulus + 1) as u16;
        if seen.insert(port) {
            candidates.push(SocketAddr::new(public_ip, port));
            if candidates.len() == level {
                break;
            }
        }
    }
    candidates
}

pub(crate) fn birthday_permutation_stride(seed: u64) -> u64 {
    let mut stride = seed % 65_534 + 1;
    for _ in 0..32 {
        if [3, 5, 17, 257]
            .into_iter()
            .all(|factor| !stride.is_multiple_of(factor))
        {
            return stride;
        }
        stride = stride % 65_534 + 1;
    }
    // A fixed bound on stride selection, even if the ring changes later.
    1
}

pub(crate) fn hard_hard_birthday_socket_count(level: usize) -> usize {
    match level {
        0..=64 => 2,
        65..=128 => 4,
        _ => 8,
    }
}

pub(crate) fn hard_hard_birthday_capacity_plan(
    requested_level: usize,
    attached_socket_count: usize,
) -> Option<(usize, usize)> {
    let requested_level = match requested_level {
        0..=64 => 64,
        65..=128 => 128,
        _ => 256,
    };
    let requested_socket_count = hard_hard_birthday_socket_count(requested_level);
    let available_socket_count = if attached_socket_count >= 8 {
        8
    } else if attached_socket_count >= 4 {
        4
    } else if attached_socket_count >= 2 {
        2
    } else {
        return None;
    };
    let actual_socket_count = available_socket_count.min(requested_socket_count);
    let actual_level = match actual_socket_count {
        2 => 64,
        4 => 128,
        8 => 256,
        _ => return None,
    };
    Some((actual_level, actual_socket_count))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BirthdaySocketPlan {
    pub(crate) requested_socket_count: usize,
    pub(crate) attached_socket_count: usize,
    pub(crate) usable_socket_count: usize,
    pub(crate) unavailable_socket_count: usize,
    pub(crate) usable_socket_indices: Vec<usize>,
}

/// Convert the exact session socket snapshot into the only socket list the
/// birthday scheduler is allowed to use.  This deliberately has no pool
/// lookup or "best effort" substitution: a missing requested member remains
/// unavailable and lowers the wave plan.
pub(crate) fn hard_hard_birthday_socket_plan(
    requested_level: usize,
    snapshot: Vec<HardHardSocketSnapshot>,
) -> BirthdaySocketPlan {
    let requested_socket_count = hard_hard_birthday_socket_count(requested_level);
    let attached_socket_count = snapshot.iter().filter(|entry| entry.attached).count();
    let usable_socket_indices = snapshot
        .into_iter()
        .filter(|entry| entry.usable)
        .map(|entry| entry.socket_index)
        .collect::<Vec<_>>();
    let usable_socket_count = usable_socket_indices.len();
    BirthdaySocketPlan {
        requested_socket_count,
        attached_socket_count,
        usable_socket_count,
        unavailable_socket_count: requested_socket_count.saturating_sub(usable_socket_count),
        usable_socket_indices,
    }
}

pub(crate) fn hard_hard_birthday_wave_count(socket_count: usize) -> usize {
    match socket_count {
        0 => 0,
        1 => 1,
        _ => HARD_HARD_BIRTHDAY_WAVES,
    }
}

pub(crate) fn hard_hard_birthday_packets_planned(
    socket_count: usize,
    target_count: usize,
) -> usize {
    target_count.saturating_mul(hard_hard_birthday_wave_count(socket_count))
}

pub(crate) fn hard_hard_birthday_wave_assignments(
    socket_count: usize,
    targets: Vec<SocketAddr>,
    _wave: usize,
) -> Vec<Vec<SocketAddr>> {
    if socket_count == 0 {
        return Vec::new();
    }
    let mut assignments = vec![Vec::new(); socket_count];
    for (index, target) in targets.into_iter().enumerate() {
        assignments[index % socket_count].push(target);
    }
    assignments
}

pub(crate) fn hard_hard_fixed_anchor_wave_assignments(
    socket_count: usize,
    anchor: SocketAddr,
) -> Vec<Vec<SocketAddr>> {
    if !matches!(socket_count, 2 | 4 | 8) || anchor.port() == 0 {
        return Vec::new();
    }
    vec![vec![anchor]; socket_count]
}
