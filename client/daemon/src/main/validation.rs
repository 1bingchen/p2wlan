// Error descriptions name the invalid option, never its untrusted value.
// They are safe to persist for a hidden desktop launch before tracing exists.
fn validate_cli(cli: &Cli) -> std::result::Result<(), &'static str> {
    if cli.manual && cli.managed {
        return Err("--manual and --managed cannot be used together");
    }

    if let Some(ref control) = cli.control {
        // Offline first-run clients have no Control service. An explicit
        // empty value is valid only when the operator selected manual mode.
        if !(cli.manual && control.is_empty()) {
            let control_url = reqwest::Url::parse(control)
                .map_err(|_| "--control must be a valid HTTP or HTTPS URL")?;
            if !matches!(control_url.scheme(), "http" | "https") {
                return Err("--control must use HTTP or HTTPS");
            }
        }
    }
    if let Some(ref network) = cli.network {
        if network.trim().is_empty() {
            return Err("--network cannot be empty");
        }
    }
    if let Some(ref addr) = cli.address {
        if addr.parse::<std::net::Ipv4Addr>().is_err() {
            return Err("--address must be a valid IPv4 address");
        }
    }
    if let Some(ref mask) = cli.netmask {
        if mask.parse::<std::net::Ipv4Addr>().is_err() {
            return Err("--netmask must be a valid IPv4 address");
        }
    }
    if let Some(mtu) = cli.mtu {
        if !(576..=65535).contains(&mtu) {
            return Err("--mtu must be between 576 and 65535");
        }
    }
    if let Some(ref bind) = cli.udp_bind {
        if bind.parse::<std::net::SocketAddr>().is_err() {
            return Err("--udp-bind must be a valid IP:port address");
        }
    }
    if let Some(ref adv) = cli.udp_advertise {
        if adv.parse::<std::net::SocketAddr>().is_err() {
            return Err("--udp-advertise must be a valid IP:port address");
        }
    }
    if let Some(ref dbind) = cli.diagnostics_bind {
        if dbind.parse::<std::net::SocketAddr>().is_err() {
            return Err("--diagnostics-bind must be a valid IP:port address");
        }
    }
    if let Some(ref stun) = cli.stun {
        for s in stun.split(',').map(str::trim).filter(|x| !x.is_empty()) {
            if !is_valid_stun_server_spec(s) {
                return Err("--stun must contain valid host:port endpoints or a disable value");
            }
        }
    }
    if let Some(ref observers) = cli.udp_observer {
        for observer in observers
            .split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
        {
            if !is_valid_stun_server_spec(observer) {
                return Err("--udp-observer must contain valid host:port endpoints or a disable value");
            }
        }
    }
    if let Some(ref relay) = cli.relay {
        for r in relay.split(',').map(str::trim).filter(|x| !x.is_empty()) {
            let endpoint = match r.split_once('@') {
                Some((region, ep)) => {
                    if region.is_empty() {
                        return Err("--relay must not contain an empty region");
                    }
                    ep
                }
                None => r,
            };
            // Reuse the transport's syntax; plaintext authorization is still
            // enforced later by the configured runtime policy.
            p2pnet_relay::tls::parse_endpoint(endpoint, true)
                .map_err(|_| "--relay must contain [region@]tls://host:port, tcp://host:port, or host:port endpoints")?;
        }
    }
    if let Some(ref socket_pool) = cli.socket_pool {
        parse_socket_pool_override(socket_pool)
            .map_err(|_| "--socket-pool must be off, on/auto, or an integer from 2 to 4")?;
    }
    if let Some(ref durl) = cli.diagnostics_url {
        let parsed = match reqwest::Url::parse(durl) {
            Ok(url) => url,
            Err(_) => return Err("--diagnostics-url must be a valid HTTP or HTTPS URL"),
        };
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err("--diagnostics-url must use HTTP or HTTPS");
        }
    }
    Ok(())
}

fn parse_socket_pool_override(value: &str) -> std::result::Result<(bool, usize), String> {
    let normalized = value.trim().to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "off" | "no" | "false" | "none" | "disable" | "disabled"
    ) {
        return Ok((false, 1));
    }

    let count = match normalized.as_str() {
        "on" | "yes" | "true" | "auto" => 3,
        raw => raw
            .parse::<usize>()
            .map_err(|_| "expected off, on/auto, or an integer from 2 to 4".to_string())?,
    };
    if !(2..=4).contains(&count) {
        return Err("expected socket count from 2 to 4".to_string());
    }
    Ok((true, count))
}

fn is_valid_stun_server_spec(value: &str) -> bool {
    let value = value.trim();
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "none" | "off" | "false" | "clear" | "unset" | "disable" | "disabled"
    ) {
        return true;
    }
    if value.parse::<std::net::SocketAddr>().is_ok() {
        return true;
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && !host.contains(char::is_whitespace)
        && !host.contains('/')
        && !host.contains('@')
        && port.parse::<u16>().is_ok_and(|port| port > 0)
}
