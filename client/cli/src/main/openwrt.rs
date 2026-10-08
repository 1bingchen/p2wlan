// The system profile has one process owner: OpenWrt's procd. Custom profiles
// retain the CLI's existing lifecycle and separate diagnostics state.

const OPENWRT_CONFIG: &str = "/etc/p2wlan/p2wlan-config.json";
const OPENWRT_STATE: &str = "/var/run/p2wlan";

fn is_openwrt() -> bool {
    cfg!(target_os = "linux") && Path::new("/etc/openwrt_release").is_file()
}

fn is_openwrt_system_profile(path: &Path) -> bool {
    is_openwrt() && same_config_path(path, Path::new(OPENWRT_CONFIG))
}

fn same_config_path(path: &Path, system: &Path) -> bool {
    path == system
        || matches!((path.canonicalize(), system.canonicalize()), (Ok(a), Ok(b)) if a == b)
}

async fn openwrt_service(action: &str) -> Result<(), String> {
    if !is_root() {
        return Err("OpenWrt 系统服务需要 root 权限".to_string());
    }
    // procd removes respawn state before stopping the process. Sending only
    // /shutdown would cause procd to restart it, and spawning a fallback daemon
    // would create a second owner for the same TUN, config and diagnostics token.
    let mut command = tokio::process::Command::new("/etc/init.d/p2wlan");
    command.arg(action).kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(45), command.status())
        .await
        .map_err(|_| format!("OpenWrt 服务 {action} 超过 45 秒，请检查 logread -e p2wlan"))?
        .map_err(|error| format!("无法执行 OpenWrt 服务 {action}：{error}"))?;
    if !status.success() {
        return Err(format!(
            "OpenWrt 服务 {action} 失败（{status}），请检查 logread -e p2wlan"
        ));
    }
    Ok(())
}

async fn start_openwrt_service(config: &Config) -> Result<(), String> {
    openwrt_service("start").await?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if fetch_status_at(&status_url(config), Path::new(OPENWRT_STATE))
            .await
            .is_ok()
        {
            println!("p2wlan 已启动，由 OpenWrt procd 管理。");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err("OpenWrt 服务在 30 秒内没有就绪，请检查 p2wlan logs 和 logread -e p2wlan".to_string())
}

#[cfg(test)]
mod openwrt_tests {
    use super::*;

    #[test]
    fn only_the_system_config_shares_procd_state() {
        let system = Path::new(OPENWRT_CONFIG);
        assert!(same_config_path(system, system));
        assert!(!same_config_path(
            Path::new("/etc/p2wlan/other.json"),
            system
        ));
        assert!(!same_config_path(
            Path::new("/tmp/p2wlan-config.json"),
            system
        ));
    }

    #[test]
    fn musl_cannot_select_a_glibc_update() {
        assert!(linux_release_arch_for("linux", "aarch64", true).is_err());
        assert!(linux_release_arch_for("linux", "x86_64", true).is_err());
        assert_eq!(
            linux_release_arch_for("linux", "aarch64", false).unwrap(),
            "arm64"
        );
        assert_eq!(
            linux_release_arch_for("linux", "x86_64", false).unwrap(),
            "x64"
        );
    }
}
