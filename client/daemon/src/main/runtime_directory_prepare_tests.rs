#[test]
fn runtime_directory_prepare_entry_is_strict_and_has_no_combined_daemon_options() {
    use std::ffi::OsString;
    for args in [
        vec!["--prepare-runtime-directory"],
        vec!["--prepare-runtime-directory", "relative"],
        vec!["--prepare-runtime-directory=/tmp/runtime"],
        vec!["--prepare-runtime-directory", "/tmp/runtime", "--managed"],
        vec!["--version", "--prepare-runtime-directory", "/tmp/runtime"],
    ] {
        let args: Vec<OsString> = args.into_iter().map(OsString::from).collect();
        assert!(parse_runtime_directory_prepare_args(&args).is_err());
    }
    assert!(parse_runtime_directory_prepare_args(&["--version".into()])
        .unwrap()
        .is_none());
    assert_eq!(
        parse_runtime_directory_prepare_args(&[
            "--prepare-runtime-directory".into(),
            "/tmp/runtime".into(),
        ])
        .unwrap(),
        Some(PathBuf::from("/tmp/runtime"))
    );
}

#[cfg(unix)]
mod runtime_directory_prepare_regressions {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    struct Fixture {
        root: PathBuf,
        home: PathBuf,
        logs: PathBuf,
        config: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let root = tempfile_directory(label).canonicalize().unwrap();
            let home = root.join("home");
            let logs = if cfg!(target_os = "macos") {
                home.join("Library/Logs/p2wlan")
            } else {
                home.join(".local/state/p2wlan")
            };
            let config = if cfg!(target_os = "macos") {
                home.join("Library/Application Support/p2wlan")
            } else {
                home.join(".config/p2wlan")
            };
            std::fs::create_dir_all(&logs).unwrap();
            std::fs::create_dir_all(&config).unwrap();
            Self {
                root,
                home,
                logs,
                config,
            }
        }

        fn prepare(&self, path: &std::path::Path) -> std::io::Result<()> {
            runtime_directory_prepare::prepare_for_test(
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                self.home.clone(),
                path,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn permissions(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn runtime_directory_prepare_requires_one_unambiguous_nonroot_caller() {
        let parse = runtime_directory_prepare::caller_uid_for_test;
        assert!(parse(None, None).is_err());
        for value in ["", "0", "-1", " 501", "501 ", "4294967295"] {
            assert!(parse(Some(OsStr::new(value)), None).is_err());
        }
        assert!(parse(Some(OsStr::new("501")), Some(OsStr::new("502"))).is_err());
        assert_eq!(parse(Some(OsStr::new("501")), None).unwrap(), 501);
        assert_eq!(parse(None, Some(OsStr::new("502"))).unwrap(), 502);
        assert_eq!(
            parse(Some(OsStr::new("501")), Some(OsStr::new("501"))).unwrap(),
            501
        );
    }

    #[test]
    fn runtime_directory_prepare_preserves_contents_and_only_repairs_allowlisted_files() {
        let fixture = Fixture::new("prepare-runtime-files");
        std::fs::set_permissions(&fixture.logs, std::fs::Permissions::from_mode(0o755)).unwrap();
        let names = [
            "p2wlan-daemon.log",
            "p2wlan-daemon.log.1",
            "p2wlan-daemon.pid",
        ];
        for name in names {
            let path = fixture.logs.join(name);
            std::fs::write(&path, name).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let credential = fixture.logs.join("p2wlan-daemon.diag-auth");
        std::fs::write(&credential, "keep-owner-and-mode").unwrap();
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o640)).unwrap();
        let unrelated = fixture.logs.join("unrelated.log");
        std::fs::write(&unrelated, "keep").unwrap();
        std::fs::set_permissions(&unrelated, std::fs::Permissions::from_mode(0o644)).unwrap();
        fixture.prepare(&fixture.logs).unwrap();
        assert_eq!(permissions(&fixture.logs), 0o700);
        for name in names {
            assert_eq!(
                std::fs::read_to_string(fixture.logs.join(name)).unwrap(),
                name
            );
            assert_eq!(permissions(&fixture.logs.join(name)), 0o600);
        }
        assert_eq!(permissions(&credential), 0o640);
        assert_eq!(permissions(&unrelated), 0o644);
        assert_eq!(
            std::fs::read_to_string(credential).unwrap(),
            "keep-owner-and-mode"
        );
    }

    #[test]
    fn runtime_directory_prepare_rejects_outside_paths_and_noncanonical_profiles() {
        let fixture = Fixture::new("prepare-runtime-scope");
        for path in [
            fixture.root.join("other"),
            fixture.home.clone(),
            fixture.logs.parent().unwrap().to_path_buf(),
            fixture.logs.join("rooms"),
            fixture.logs.join("accounts").join("a".repeat(64)),
            fixture.logs.join("rooms").join("A".repeat(64)),
            fixture.config.join("accounts").join("a".repeat(63)),
            fixture
                .config
                .join("rooms")
                .join("a".repeat(64))
                .join("more"),
            fixture.logs.join("..").join("p2wlan"),
        ] {
            assert!(
                fixture.prepare(&path).is_err(),
                "unexpected acceptance: {path:?}"
            );
        }
        for scope in ["accounts", "rooms"] {
            let profile = fixture.config.join(scope).join("a".repeat(64));
            fixture.prepare(&profile).unwrap();
            assert_eq!(permissions(&profile), 0o700);
        }
    }

    #[test]
    fn runtime_directory_prepare_rejects_symlinks_hardlinks_and_special_files_before_chmod() {
        let fixture = Fixture::new("prepare-runtime-links");
        let outside = fixture.root.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::remove_dir(&fixture.logs).unwrap();
        std::os::unix::fs::symlink(&outside, &fixture.logs).unwrap();
        assert!(fixture.prepare(&fixture.logs).is_err());
        std::fs::remove_file(&fixture.logs).unwrap();
        std::fs::create_dir(&fixture.logs).unwrap();
        std::fs::set_permissions(&fixture.logs, std::fs::Permissions::from_mode(0o755)).unwrap();
        let source = outside.join("source");
        std::fs::write(&source, "unchanged").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644)).unwrap();
        let leaf = fixture.logs.join("p2wlan-daemon.log");
        std::os::unix::fs::symlink(&source, &leaf).unwrap();
        assert!(fixture.prepare(&fixture.logs).is_err());
        std::fs::remove_file(&leaf).unwrap();
        std::fs::hard_link(&source, &leaf).unwrap();
        assert!(fixture.prepare(&fixture.logs).is_err());
        std::fs::remove_file(&leaf).unwrap();
        std::fs::create_dir(&leaf).unwrap();
        assert!(fixture.prepare(&fixture.logs).is_err());
        assert_eq!(permissions(&fixture.logs), 0o755);
        assert_eq!(permissions(&source), 0o644);
        assert_eq!(std::fs::read_to_string(source).unwrap(), "unchanged");
    }

    #[test]
    fn runtime_directory_prepare_refuses_active_namespace_without_replacing_locks() {
        let fixture = Fixture::new("prepare-runtime-lock");
        std::fs::set_permissions(&fixture.logs, std::fs::Permissions::from_mode(0o755)).unwrap();
        for name in ["p2wlan-daemon.diag-auth.lock", "p2wlan-config.json.lock"] {
            let path = fixture.logs.join(name);
            std::fs::write(&path, "lock contents").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            let held = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            fs2::FileExt::try_lock_exclusive(&held).unwrap();
            let before = held.metadata().unwrap();
            assert!(fixture.prepare(&fixture.logs).is_err());
            assert_eq!(permissions(&fixture.logs), 0o755);
            drop(held);
            fixture.prepare(&fixture.logs).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().ino(), before.ino());
            assert_eq!(permissions(&path), 0o640);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "lock contents");
            std::fs::remove_file(path).unwrap();
            std::fs::set_permissions(&fixture.logs, std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
    }

    #[test]
    fn runtime_directory_prepare_account_config_honors_the_shared_log_namespace_lock() {
        let fixture = Fixture::new("prepare-runtime-account-lock");
        let profile = fixture.config.join("accounts").join("a".repeat(64));
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = fixture.logs.join("p2wlan-daemon.diag-auth.lock");
        let held = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        fs2::FileExt::try_lock_exclusive(&held).unwrap();
        assert!(fixture.prepare(&profile).is_err());
        assert_eq!(permissions(&profile), 0o755);
    }

    #[test]
    #[ignore = "requires root to exercise root-owned Unix runtime recovery"]
    fn runtime_directory_prepare_privileged_root_owned_paths_preserve_data_and_foreign_owners() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "requires root; never silently skip"
        );
        use std::os::unix::ffi::OsStrExt;
        let fixture = Fixture::new("prepare-runtime-privileged");
        let uid = 65534;
        let gid = 65534;
        let chown = |path: &std::path::Path, uid, gid| {
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(path.as_ptr(), uid, gid) }, 0);
        };
        chown(&fixture.home, uid, gid);
        for app in [&fixture.logs, &fixture.config] {
            let mut parent = app.parent().unwrap();
            while parent != fixture.home {
                chown(parent, uid, gid);
                parent = parent.parent().unwrap();
            }
        }
        let log = fixture.logs.join("p2wlan-daemon.log");
        std::fs::write(&log, "preserve-root-log").unwrap();
        let prepare = |path: &std::path::Path| {
            runtime_directory_prepare::prepare_for_test(uid, gid, fixture.home.clone(), path)
        };
        prepare(&fixture.logs).unwrap();
        assert_eq!(std::fs::metadata(&fixture.logs).unwrap().uid(), uid);
        assert_eq!(std::fs::metadata(&log).unwrap().uid(), uid);
        assert_eq!(permissions(&log), 0o600);
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "preserve-root-log");
        chown(&fixture.config, 65533, 65533);
        assert!(prepare(&fixture.config).is_err());
        assert_eq!(std::fs::metadata(&fixture.config).unwrap().uid(), 65533);
    }
}
