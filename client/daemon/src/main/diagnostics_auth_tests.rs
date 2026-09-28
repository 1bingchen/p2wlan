#[cfg(unix)]
#[test]
fn diagnostics_auth_owner_override_is_only_selected_for_root() {
    assert_eq!(
        diagnostics_owner_for_euid(0, 501, 20),
        Some(DiagnosticsAuthOwner { uid: 501, gid: 20 })
    );
    assert_eq!(diagnostics_owner_for_euid(501, 502, 20), None);
    assert_eq!(diagnostics_owner_for_euid(501, 0, 0), None);
}

#[test]
fn diagnostics_auth_discovery_lock_rejects_different_configs_in_one_directory() {
    let directory = tempfile_directory("diagnostics-shared-directory");
    let first_path = directory.join("first.json");
    let second_path = directory.join("second.json");
    std::fs::write(&first_path, b"{}").unwrap();
    std::fs::write(&second_path, b"{}").unwrap();
    let first_instance = DaemonInstanceLock::acquire(&first_path).unwrap();
    let second_instance = DaemonInstanceLock::acquire(&second_path).unwrap();
    let mut first_config = diagnostics_test_config(&directory);
    let first = DiagnosticsAuthGuard::prepare(&mut first_config, &first_path, None)
        .unwrap()
        .unwrap();
    let mut second_config = diagnostics_test_config(&directory);
    let second = DiagnosticsAuthGuard::prepare(&mut second_config, &second_path, None);
    assert!(
        second.is_err(),
        "config locks must not bypass discovery ownership"
    );
    assert!(second_config.diagnostics.auth_token.is_none());
    assert!(second_config.diagnostics.auth_token_path.is_none());
    assert!(auth_file_matches(&first.path, first.token.as_str()));

    drop(first);
    assert!(directory.join("p2wlan-daemon.diag-auth.lock").is_file());
    let second = DiagnosticsAuthGuard::prepare(&mut second_config, &second_path, None)
        .unwrap()
        .unwrap();
    assert!(auth_file_matches(&second.path, second.token.as_str()));
    drop(second);
    drop(first_instance);
    drop(second_instance);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn diagnostics_auth_discovery_lock_allows_independent_directories() {
    let first_directory = tempfile_directory("diagnostics-independent-first");
    let second_directory = tempfile_directory("diagnostics-independent-second");
    let mut first_config = diagnostics_test_config(&first_directory);
    let mut second_config = diagnostics_test_config(&second_directory);
    let first = DiagnosticsAuthGuard::prepare(
        &mut first_config,
        &first_directory.join("config.json"),
        None,
    )
    .unwrap()
    .unwrap();
    let second = DiagnosticsAuthGuard::prepare(
        &mut second_config,
        &second_directory.join("config.json"),
        None,
    )
    .unwrap()
    .unwrap();
    assert!(auth_file_matches(&first.path, first.token.as_str()));
    assert!(auth_file_matches(&second.path, second.token.as_str()));
    drop(first);
    assert!(auth_file_matches(&second.path, second.token.as_str()));
    drop(second);
    std::fs::remove_dir_all(first_directory).unwrap();
    std::fs::remove_dir_all(second_directory).unwrap();
}

#[test]
fn diagnostics_auth_drop_preserves_replaced_token_and_closes_late_repair() {
    let directory = tempfile_directory("diagnostics-drop-replacement");
    let mut config = diagnostics_test_config(&directory);
    let guard = DiagnosticsAuthGuard::prepare(&mut config, &directory.join("config.json"), None)
        .unwrap()
        .unwrap();
    let path = guard.path.clone();
    let owner = capture_diagnostics_auth_owner(&directory).unwrap();
    let late_repair = guard.repair_lock.clone();
    std::fs::write(&path, b"replacement-session").unwrap();
    drop(guard);
    assert!(auth_file_matches(&path, "replacement-session"));
    std::fs::remove_dir_all(&directory).unwrap();

    // An aborted task may have already been blocked on this synchronous mutex.
    // Exercise the actual repair body after Drop released it; None is terminal.
    let result = repair_auth_file_if_needed(
        &mut late_repair.lock().unwrap(),
        &path,
        "retired-session",
        owner,
        None,
    )
    .unwrap();
    assert_eq!(result, DiagnosticsAuthRepair::Closed);
    assert!(!directory.exists());
}

#[test]
fn diagnostics_auth_read_rejects_non_files_and_oversized_content() {
    let directory = tempfile_directory("diagnostics-bounded-read");
    let path = directory.join("token");
    std::fs::write(&path, b"known-test-token\n").unwrap();
    assert!(auth_file_matches(&path, "known-test-token"));
    std::fs::write(&path, format!("known-test-token{}", " ".repeat(4096))).unwrap();
    assert!(!auth_file_matches(&path, "known-test-token"));
    assert!(!auth_file_matches(&directory, "known-test-token"));
    #[cfg(unix)]
    {
        std::fs::write(&path, b"known-test-token").unwrap();
        let alias = directory.join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(!auth_file_matches(&alias, "known-test-token"));
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn diagnostics_auth_canonical_directory_alias_cannot_create_second_owner() {
    let directory = tempfile_directory("diagnostics-canonical-directory");
    let real_directory = directory.join("real");
    std::fs::create_dir(&real_directory).unwrap();
    let alias = directory.join("alias");
    std::os::unix::fs::symlink(&real_directory, &alias).unwrap();
    let mut first_config = diagnostics_test_config(&real_directory);
    let first =
        DiagnosticsAuthGuard::prepare(&mut first_config, &directory.join("first.json"), None)
            .unwrap()
            .unwrap();
    let mut second_config = diagnostics_test_config(&alias);
    assert!(DiagnosticsAuthGuard::prepare(
        &mut second_config,
        &directory.join("second.json"),
        None,
    )
    .is_err());
    assert!(auth_file_matches(&first.path, first.token.as_str()));
    drop(first);
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn diagnostics_auth_lock_rejects_linked_inodes_before_permission_changes() {
    use std::os::unix::fs::PermissionsExt;

    let directory = std::fs::canonicalize(tempfile_directory("diagnostics-linked-lock")).unwrap();
    let target = directory.join("unrelated-file");
    let lock_path = directory.join("p2wlan-daemon.diag-auth.lock");
    std::fs::write(&target, b"unrelated-data").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
    std::fs::hard_link(&target, &lock_path).unwrap();
    let owner = capture_diagnostics_auth_owner(&directory).unwrap();
    assert!(DiagnosticsDiscoveryLock::acquire(&directory, owner, None).is_err());
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"unrelated-data");
    std::fs::remove_file(&lock_path).unwrap();
    std::os::unix::fs::symlink(&target, &lock_path).unwrap();
    assert!(DiagnosticsDiscoveryLock::acquire(&directory, owner, None).is_err());
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o640
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn diagnostics_auth_retired_directory_owner_cannot_overwrite_or_delete_successor() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory =
        std::fs::canonicalize(tempfile_directory("diagnostics-directory-successor")).unwrap();
    let mut first_config = diagnostics_test_config(&directory);
    let first =
        DiagnosticsAuthGuard::prepare(&mut first_config, &directory.join("first.json"), None)
            .unwrap()
            .unwrap();
    let owner = capture_diagnostics_auth_owner(&directory).unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
    std::fs::create_dir(&directory).unwrap();
    let mut second_config = diagnostics_test_config(&directory);
    let second =
        DiagnosticsAuthGuard::prepare(&mut second_config, &directory.join("second.json"), None)
            .unwrap()
            .unwrap();
    // A failed contender must not tighten or change even a successor's
    // intentionally different directory/lock metadata before losing flock.
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o750)).unwrap();
    let lock_path = directory.join("p2wlan-daemon.diag-auth.lock");
    std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let metadata_snapshot = |path: &std::path::Path| {
        let metadata = std::fs::metadata(path).unwrap();
        (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
        )
    };
    let directory_before = metadata_snapshot(&directory);
    let lock_before = metadata_snapshot(&lock_path);
    assert!(
        repair_auth_file_if_needed(
            &mut first.repair_lock.lock().unwrap(),
            &first.path,
            first.token.as_str(),
            owner,
            None,
        )
        .is_err(),
        "a detached lock inode must not authorize publication"
    );
    assert!(auth_file_matches(&second.path, second.token.as_str()));
    assert_eq!(metadata_snapshot(&directory), directory_before);
    assert_eq!(metadata_snapshot(&lock_path), lock_before);
    drop(first);
    assert!(auth_file_matches(&second.path, second.token.as_str()));
    assert_eq!(metadata_snapshot(&directory), directory_before);
    assert_eq!(metadata_snapshot(&lock_path), lock_before);
    assert!(DiagnosticsDiscoveryLock::acquire(&directory, owner, None).is_err());
    drop(second);
    assert!(!directory.join("p2wlan-daemon.diag-auth").exists());
    assert!(directory.join("p2wlan-daemon.diag-auth.lock").is_file());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires root; CI explicitly runs this isolated ownership regression with sudo"]
async fn diagnostics_auth_privileged_owner_survives_repair() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "this regression must execute as root"
    );
    let directory = tempfile_directory("diagnostics-privileged-owner");
    let directory_file = std::fs::File::open(&directory).unwrap();
    let owner = DiagnosticsAuthOwner {
        uid: 65534,
        gid: 65534,
    };
    assert_eq!(
        unsafe { libc::fchown(directory_file.as_raw_fd(), owner.uid, owner.gid) },
        0
    );
    drop(directory_file);
    let mut config = diagnostics_test_config(&directory);
    let guard = DiagnosticsAuthGuard::prepare(&mut config, &directory.join("config.json"), None)
        .unwrap()
        .unwrap();
    let assert_owner = |path: &std::path::Path| {
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (owner.uid, owner.gid));
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        metadata.ino()
    };
    let assert_directory_owner = || {
        let metadata = std::fs::metadata(&directory).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (owner.uid, owner.gid));
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    };
    assert_directory_owner();
    let initial_inode = assert_owner(&guard.path);
    assert_owner(&directory.join("p2wlan-daemon.diag-auth.lock"));
    assert!(auth_file_matches(&guard.path, guard.token.as_str()));
    let initial_file = std::fs::File::open(&guard.path).unwrap();
    std::fs::remove_file(&guard.path).unwrap();
    wait_for_auth_file(&guard.path, guard.token.as_str()).await;
    let repaired_inode = assert_owner(&guard.path);
    assert_ne!(repaired_inode, initial_inode);
    drop(initial_file);

    // Keep the previous inode alive so inode inequality is deterministic even
    // when the filesystem aggressively reuses deleted inode numbers.
    let repaired_file = std::fs::File::open(&guard.path).unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
    wait_for_auth_file(&guard.path, guard.token.as_str()).await;
    assert_ne!(assert_owner(&guard.path), repaired_inode);
    assert_owner(&directory.join("p2wlan-daemon.diag-auth.lock"));
    assert_directory_owner();
    assert!(auth_file_matches(&guard.path, guard.token.as_str()));
    drop(repaired_file);
    drop(guard);
    assert!(!directory.join("p2wlan-daemon.diag-auth").exists());
    std::fs::remove_dir_all(directory).unwrap();
    diagnostics_auth_privileged_repair_rejects_foreign_directory(owner);
}

#[cfg(unix)]
fn diagnostics_auth_privileged_repair_rejects_foreign_directory(owner: DiagnosticsAuthOwner) {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory = tempfile_directory("diagnostics-foreign-directory");
    let file = std::fs::File::open(&directory).unwrap();
    assert_eq!(
        unsafe { libc::fchown(file.as_raw_fd(), owner.uid, owner.gid) },
        0
    );
    drop(file);
    let mut config = diagnostics_test_config(&directory);
    let guard = DiagnosticsAuthGuard::prepare(&mut config, &directory.join("config.json"), None)
        .unwrap()
        .unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
    std::fs::create_dir(&directory).unwrap();
    let successor_directory = std::fs::File::open(&directory).unwrap();
    let foreign_uid = owner.uid - 1;
    assert_eq!(
        unsafe { libc::fchown(successor_directory.as_raw_fd(), foreign_uid, owner.gid) },
        0
    );
    successor_directory
        .set_permissions(std::fs::Permissions::from_mode(0o751))
        .unwrap();
    let before = successor_directory.metadata().unwrap();
    assert!(repair_auth_file_if_needed(
        &mut guard.repair_lock.lock().unwrap(),
        &guard.path,
        guard.token.as_str(),
        Some(owner),
        None,
    )
    .is_err());
    drop(guard);
    let after = std::fs::metadata(&directory).unwrap();
    assert_eq!(
        (after.uid(), after.gid(), after.mode()),
        (before.uid(), before.gid(), before.mode())
    );
    assert!(!directory.join("p2wlan-daemon.diag-auth.lock").exists());
    assert!(!directory.join("p2wlan-daemon.diag-auth").exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn diagnostics_auth_repair_rejects_redirected_directory_without_touching_target() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    for replace_ancestor in [false, true] {
        let root = std::fs::canonicalize(tempfile_directory("diagnostics-directory-link")).unwrap();
        let parent = root.join("parent");
        let directory = parent.join("runtime");
        std::fs::create_dir_all(&directory).unwrap();
        let mut config = diagnostics_test_config(&directory);
        let guard =
            DiagnosticsAuthGuard::prepare(&mut config, &directory.join("config.json"), None)
                .unwrap()
                .unwrap();
        let owner = capture_diagnostics_auth_owner(&directory).unwrap();
        let target = root.join("unrelated");
        std::fs::create_dir_all(target.join("runtime")).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o751)).unwrap();
        let marker = target.join("keep");
        std::fs::write(&marker, b"unchanged").unwrap();
        let before = std::fs::metadata(&target).unwrap();
        let replaced = if replace_ancestor {
            &parent
        } else {
            &directory
        };
        std::fs::rename(replaced, root.join("retired")).unwrap();
        std::os::unix::fs::symlink(&target, replaced).unwrap();
        assert!(repair_auth_file_if_needed(
            &mut guard.repair_lock.lock().unwrap(),
            &guard.path,
            guard.token.as_str(),
            owner,
            None,
        )
        .is_err());
        drop(guard);
        let after = std::fs::metadata(&target).unwrap();
        assert_eq!(
            (after.uid(), after.gid(), after.mode()),
            (before.uid(), before.gid(), before.mode())
        );
        assert_eq!(std::fs::read(&marker).unwrap(), b"unchanged");
        assert!(!target.join("p2wlan-daemon.diag-auth").exists());
        assert!(!target.join("runtime/p2wlan-daemon.diag-auth").exists());
        assert!(!target.join("p2wlan-daemon.diag-auth.lock").exists());
        assert!(!target.join("runtime/p2wlan-daemon.diag-auth.lock").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn diagnostics_auth_publication_cannot_recreate_a_retired_directory() {
    let directory =
        std::fs::canonicalize(tempfile_directory("diagnostics-retired-publication")).unwrap();
    let owner = capture_diagnostics_auth_owner(&directory).unwrap();
    let lock = DiagnosticsDiscoveryLock::acquire(&directory, owner, None).unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
    assert!(publish_auth_file(
        &lock,
        &directory.join("p2wlan-daemon.diag-auth"),
        "test-token",
        owner,
        None,
    )
    .is_err());
    assert!(
        !directory.exists(),
        "publication must not create an unowned namespace"
    );
}

#[cfg(unix)]
#[test]
fn diagnostics_auth_repair_does_not_recreate_missing_ancestors() {
    let root = std::fs::canonicalize(tempfile_directory("diagnostics-missing-ancestor")).unwrap();
    let parent = root.join("parent");
    let directory = parent.join("runtime");
    std::fs::create_dir_all(&directory).unwrap();
    let mut config = diagnostics_test_config(&directory);
    let guard = DiagnosticsAuthGuard::prepare(&mut config, &directory.join("config.json"), None)
        .unwrap()
        .unwrap();
    let owner = capture_diagnostics_auth_owner(&directory).unwrap();
    std::fs::remove_dir_all(&parent).unwrap();
    assert!(repair_auth_file_if_needed(
        &mut guard.repair_lock.lock().unwrap(),
        &guard.path,
        guard.token.as_str(),
        owner,
        None,
    )
    .is_err());
    drop(guard);
    assert!(
        !parent.exists(),
        "the repair owner is limited to its exact leaf directory"
    );
    std::fs::remove_dir_all(root).unwrap();
}
