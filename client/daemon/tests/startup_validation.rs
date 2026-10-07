//! Exercise the actual desktop daemon entry point without TUN or network I/O.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

struct StartupDirectory(PathBuf);

impl StartupDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "p2wlan-startup-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn config(&self) -> PathBuf {
        self.0.join("config.json")
    }

    fn log(&self) -> PathBuf {
        self.0.join("daemon.log")
    }

    fn run(&self, args: &[&str]) -> ExitStatus {
        let mut child = Command::new(env!("CARGO_BIN_EXE_p2wlan-daemon"))
            .current_dir(&self.0)
            .env("P2WLAN_DISABLE_TUN", "1")
            .args(["--config", self.config().to_str().unwrap()])
            .args(["--log-file", self.log().to_str().unwrap()])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("daemon startup validation did not finish within 15 seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for StartupDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn read_config(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn offline_desktop_start_accepts_an_empty_control_address() {
    let root = StartupDirectory::new();
    // The first-run desktop client sends this explicit empty value when the
    // user selects offline mode without configuring a Control service.
    assert!(root.run(&["--manual", "--control", "", "--init"]).success());
    let config = read_config(&root.config());
    assert_eq!(config["network"]["manual"], true);
    assert_eq!(config["control"]["server_url"], "");
}

#[test]
fn relay_cli_accepts_the_runtime_tls_and_hostname_formats() {
    let root = StartupDirectory::new();
    let relays = "eu@tls://relay.example.com:443,tcp://127.0.0.1:18081,[::1]:18081";
    assert!(root
        .run(&[
            "--manual",
            "--control",
            "https://control.example.com",
            "--relay",
            relays,
            "--init",
        ])
        .success());
    let config = read_config(&root.config());
    assert_eq!(
        config["relay"]["servers"],
        serde_json::json!(relays.split(',').collect::<Vec<_>>())
    );
    // Syntax acceptance must not enable plaintext transport policy.
    assert_eq!(config["relay"]["allow_insecure_plaintext"], false);
}

#[test]
fn invalid_startup_settings_leave_private_actionable_logs_without_values() {
    for args in [
        vec!["--managed", "--control", ""],
        vec![
            "--manual",
            "--control",
            "ssh://private-user:secret-value@example.com",
        ],
        vec!["--manual", "--address", "secret-value"],
        vec!["--manual", "--relay", "secret-value"],
    ] {
        let root = StartupDirectory::new();
        assert!(!root.run(&args).success());
        assert!(!root.config().exists());
        let log = std::fs::read_to_string(root.log()).unwrap();
        assert!(log.contains("STARTUP_CONFIG_INVALID"), "{log}");
        assert!(!log.contains("secret-value"), "{log}");
        assert!(!log.contains("private-user"), "{log}");
        assert!(log.len() < 512, "startup diagnostics must remain bounded");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(root.log()).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn help_and_version_remain_free_of_startup_side_effects() {
    for arg in ["--help", "--version", "--build-info"] {
        let root = StartupDirectory::new();
        assert!(root.run(&[arg]).success());
        assert!(!root.log().exists());
        assert!(!root.config().exists());
    }
}

#[cfg(unix)]
#[test]
fn early_errors_do_not_follow_symlinks_or_modify_hard_link_targets() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for hard_link in [false, true] {
        let root = StartupDirectory::new();
        let target = root.0.join("unrelated.txt");
        std::fs::write(&target, "unchanged").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        if hard_link {
            std::fs::hard_link(&target, root.log()).unwrap();
        } else {
            symlink(&target, root.log()).unwrap();
        }
        assert!(!root.run(&["--managed", "--control", ""]).success());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "unchanged");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}
