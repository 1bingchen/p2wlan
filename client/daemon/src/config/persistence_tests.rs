use super::Config;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

struct ConfigDirectory(PathBuf);

impl ConfigDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "p2wlan-private-config-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn config_path(&self) -> PathBuf {
        self.0.join("p2wlan-config.json")
    }

    fn assert_no_pending_files(&self) {
        assert!(!fs::read_dir(&self.0).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".p2wlan-config-")
        }));
    }
}

impl Drop for ConfigDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn config_atomic_save_keeps_private_mode_and_leaves_no_temporary_file() {
    let directory = ConfigDirectory::new();
    let path = directory.config_path();
    let mut config = Config::generate_default("https://ctrl.test", "first").unwrap();
    config.save_to_file(&path).unwrap();
    let first = fs::metadata(&path).unwrap();
    assert_eq!(first.permissions().mode() & 0o777, 0o600);
    assert_eq!(first.nlink(), 1);
    config.network.network_id = "second".to_string();
    config.save_to_file(&path).unwrap();
    let second = fs::metadata(&path).unwrap();
    assert_eq!(second.permissions().mode() & 0o777, 0o600);
    assert_eq!((second.uid(), second.gid()), (first.uid(), first.gid()));
    assert_eq!(
        Config::load_from_file(&path).unwrap().network.network_id,
        "second"
    );
    directory.assert_no_pending_files();
}

#[test]
fn config_save_does_not_open_the_old_predictable_temporary_path() {
    let directory = ConfigDirectory::new();
    let path = directory.config_path();
    let unrelated = directory.0.join("unrelated");
    fs::write(&unrelated, "unchanged").unwrap();
    fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o640)).unwrap();
    let old_temporary_path = path.with_extension("tmp");
    std::os::unix::fs::symlink(&unrelated, &old_temporary_path).unwrap();
    Config::generate_default("https://ctrl.test", "net")
        .unwrap()
        .save_to_file(&path)
        .unwrap();
    assert_eq!(fs::read_to_string(&unrelated).unwrap(), "unchanged");
    assert_eq!(
        fs::metadata(&unrelated).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert!(fs::symlink_metadata(old_temporary_path)
        .unwrap()
        .file_type()
        .is_symlink());
    directory.assert_no_pending_files();
}

#[test]
fn config_save_rejects_linked_targets_without_mutating_their_source() {
    let directory = ConfigDirectory::new();
    let path = directory.config_path();
    let unrelated = directory.0.join("unrelated");
    fs::write(&unrelated, "unchanged").unwrap();
    fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o640)).unwrap();
    let config = Config::generate_default("https://ctrl.test", "net").unwrap();
    std::os::unix::fs::symlink(&unrelated, &path).unwrap();
    assert!(config.save_to_file(&path).is_err());
    assert!(fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    fs::remove_file(&path).unwrap();
    fs::hard_link(&unrelated, &path).unwrap();
    assert!(config.save_to_file(&path).is_err());
    assert_eq!(fs::metadata(&path).unwrap().nlink(), 2);
    assert_eq!(fs::read_to_string(&unrelated).unwrap(), "unchanged");
    assert_eq!(
        fs::metadata(&unrelated).unwrap().permissions().mode() & 0o777,
        0o640
    );
    directory.assert_no_pending_files();
}

#[test]
fn config_save_rejects_a_symlink_config_directory() {
    let directory = ConfigDirectory::new();
    let real = directory.0.join("real");
    fs::create_dir(&real).unwrap();
    let alias = directory.0.join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let config = Config::generate_default("https://ctrl.test", "net").unwrap();
    assert!(config.save_to_file(&alias.join("config.json")).is_err());
    assert_eq!(fs::read_dir(real).unwrap().count(), 0);
}

#[test]
#[ignore = "requires root; CI runs this isolated directory-ownership regression explicitly"]
fn privileged_config_save_inherits_pinned_directory_owner() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "this regression requires root"
    );
    let directory = ConfigDirectory::new();
    let directory_file = File::open(&directory.0).unwrap();
    let (uid, gid) = (65534, 65534);
    assert_eq!(
        unsafe { libc::fchown(directory_file.as_raw_fd(), uid, gid) },
        0
    );
    let path = directory.config_path();
    let config = Config::generate_default("https://ctrl.test", "net").unwrap();
    let assert_owner = || {
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (uid, gid));
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    };
    config.save_to_file(&path).unwrap();
    assert_owner();
    config.save_to_file(&path).unwrap();
    assert_owner();

    // A stale root-created current config is repaired through replacement;
    // no recursive repair or mutation of neighboring files is needed.
    let current = File::open(&path).unwrap();
    assert_eq!(unsafe { libc::fchown(current.as_raw_fd(), 0, 0) }, 0);
    drop(current);
    config.save_to_file(&path).unwrap();
    assert_owner();

    // A different user's inode must not be silently overwritten even when
    // root could technically do so inside this directory.
    let current = File::open(&path).unwrap();
    assert_eq!(
        unsafe { libc::fchown(current.as_raw_fd(), 65533, 65533) },
        0
    );
    drop(current);
    let before = fs::read(&path).unwrap();
    let inode = fs::metadata(&path).unwrap().ino();
    assert!(config.save_to_file(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.ino(), inode);
    assert_eq!((metadata.uid(), metadata.gid()), (65533, 65533));
    directory.assert_no_pending_files();
}
