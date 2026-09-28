const RUNTIME_DIRECTORY_PREPARE_FLAG: &str = "--prepare-runtime-directory";

fn parse_runtime_directory_prepare_args(
    args: &[std::ffi::OsString],
) -> p2pnet_daemon::Result<Option<PathBuf>> {
    if !args.iter().any(|arg| {
        arg == RUNTIME_DIRECTORY_PREPARE_FLAG
            || arg
                .to_string_lossy()
                .starts_with("--prepare-runtime-directory=")
    }) {
        return Ok(None);
    }
    if args.len() != 2 || args[0] != RUNTIME_DIRECTORY_PREPARE_FLAG {
        return Err(DaemonError::Config(
            "runtime_directory_prepare: expected only --prepare-runtime-directory ABSOLUTE_PATH"
                .into(),
        ));
    }
    let path = PathBuf::from(&args[1]);
    if !path.is_absolute() {
        return Err(DaemonError::Config(
            "runtime_directory_prepare: path must be absolute".into(),
        ));
    }
    Ok(Some(path))
}

fn run_runtime_directory_prepare_from_process_args() -> p2pnet_daemon::Result<bool> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let Some(path) = parse_runtime_directory_prepare_args(&args)? else {
        return Ok(false);
    };
    #[cfg(unix)]
    runtime_directory_prepare::run(&path)
        .map_err(|error| DaemonError::Config(format!("runtime_directory_prepare: {error}")))?;
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(DaemonError::Config(
            "runtime_directory_prepare: unsupported platform".into(),
        ))
    }
    #[cfg(unix)]
    {
        println!("runtime_directory_prepared");
        Ok(true)
    }
}

#[cfg(unix)]
mod runtime_directory_prepare {
    use std::ffi::{CStr, CString, OsStr, OsString};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    struct Caller {
        uid: libc::uid_t,
        gid: libc::gid_t,
        home: PathBuf,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DirectoryKind {
        Logs,
        Config,
    }

    struct Location {
        kind: DirectoryKind,
        suffix: Vec<OsString>,
    }

    struct NamespaceLock {
        directory: File,
        name: &'static str,
        held: Option<File>,
    }

    impl NamespaceLock {
        fn verify_current(&self, caller: &Caller) -> io::Result<()> {
            let current = optional_file(&self.directory, self.name, caller)?;
            match (&self.held, current) {
                (None, None) => Ok(()),
                (Some(held), Some(current)) => {
                    let held = held.metadata()?;
                    let current = current.metadata()?;
                    if (held.dev(), held.ino()) == (current.dev(), current.ino()) {
                        Ok(())
                    } else {
                        Err(denied("runtime_namespace_changed"))
                    }
                }
                _ => Err(denied("runtime_namespace_changed")),
            }
        }
    }

    fn denied(reason: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, reason)
    }

    fn caller_uid(sudo: Option<&OsStr>, pkexec: Option<&OsStr>) -> io::Result<libc::uid_t> {
        let parse = |value: &OsStr| {
            value
                .to_str()
                .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|text| text.parse::<libc::uid_t>().ok())
                .filter(|uid| *uid != 0 && *uid != libc::uid_t::MAX)
                .ok_or_else(|| denied("invalid_caller_uid"))
        };
        match (sudo.map(parse).transpose()?, pkexec.map(parse).transpose()?) {
            (Some(a), Some(b)) if a != b => Err(denied("ambiguous_caller_uid")),
            (Some(uid), _) | (_, Some(uid)) => Ok(uid),
            _ => Err(denied("missing_caller_uid")),
        }
    }

    fn lookup_caller(uid: libc::uid_t) -> io::Result<Caller> {
        // Bound NSS storage; do not infer a privileged caller from HOME/USER.
        let mut buffer = vec![0u8; 65_536];
        let mut passwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                passwd.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if result.is_null() {
            return Err(denied("caller_account_missing"));
        }
        let passwd = unsafe { passwd.assume_init() };
        if passwd.pw_uid != uid || passwd.pw_dir.is_null() {
            return Err(denied("invalid_caller_account"));
        }
        let home = unsafe { CStr::from_ptr(passwd.pw_dir) }.to_bytes();
        let home = PathBuf::from(OsString::from_vec(home.to_vec()));
        if components(&home)?.is_empty() {
            return Err(denied("invalid_caller_home"));
        }
        Ok(Caller {
            uid,
            gid: passwd.pw_gid,
            home,
        })
    }

    fn components(path: &Path) -> io::Result<Vec<OsString>> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.len() > 4096 || bytes.first() != Some(&b'/') {
            return Err(denied("invalid_absolute_path"));
        }
        let mut parts = Vec::new();
        for part in bytes[1..].split(|byte| *byte == b'/') {
            if part.is_empty() || part == b"." || part == b".." || part.contains(&0) {
                return Err(denied("noncanonical_path_component"));
            }
            parts.push(OsString::from_vec(part.to_vec()));
        }
        Ok(parts)
    }

    fn app_prefix(kind: DirectoryKind) -> &'static [&'static str] {
        match (cfg!(target_os = "macos"), kind) {
            (true, DirectoryKind::Logs) => &["Library", "Logs", "p2wlan"],
            (true, DirectoryKind::Config) => &["Library", "Application Support", "p2wlan"],
            (false, DirectoryKind::Logs) => &[".local", "state", "p2wlan"],
            (false, DirectoryKind::Config) => &[".config", "p2wlan"],
        }
    }

    fn location(caller: &Caller, path: &Path) -> io::Result<Location> {
        let home = components(&caller.home)?;
        let path = components(path)?;
        let relative = path
            .strip_prefix(home.as_slice())
            .ok_or_else(|| denied("path_outside_caller_home"))?;
        for kind in [DirectoryKind::Logs, DirectoryKind::Config] {
            let prefix: Vec<OsString> = app_prefix(kind).iter().map(OsString::from).collect();
            let Some(suffix) = relative.strip_prefix(prefix.as_slice()) else {
                continue;
            };
            let valid = suffix.is_empty()
                || (suffix.len() == 2
                    && (suffix[0] == "rooms"
                        || (kind == DirectoryKind::Config && suffix[0] == "accounts"))
                    && suffix[1].as_bytes().len() == 64
                    && suffix[1]
                        .as_bytes()
                        .iter()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)));
            if valid {
                return Ok(Location {
                    kind,
                    suffix: suffix.to_vec(),
                });
            }
        }
        Err(denied("path_not_allowlisted"))
    }

    fn open_at(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
        let name = CString::new(name.as_bytes()).map_err(|_| denied("invalid_component"))?;
        let mode = if directory {
            libc::O_DIRECTORY
        } else {
            libc::O_NONBLOCK
        };
        let access = if directory {
            libc::O_RDONLY
        } else {
            libc::O_RDWR
        };
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                access | mode | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    fn owned(file: &File, caller: &Caller, root_allowed: bool) -> io::Result<()> {
        let uid = file.metadata()?.uid();
        if uid != caller.uid && !(root_allowed && uid == 0) {
            return Err(denied("foreign_owner"));
        }
        Ok(())
    }

    fn open_home(caller: &Caller) -> io::Result<File> {
        let mut parent = File::open("/")?;
        let parts = components(&caller.home)?;
        for (index, name) in parts.iter().enumerate() {
            parent = open_at(&parent, name, true)?;
            owned(&parent, caller, index + 1 != parts.len())?;
        }
        Ok(parent)
    }

    fn open_app(
        caller: &Caller,
        home: &File,
        location: &Location,
        create: bool,
    ) -> io::Result<Vec<File>> {
        let prefix = app_prefix(location.kind);
        let mut parent = home.try_clone()?;
        let mut app = Vec::new();
        for (index, name) in prefix
            .iter()
            .map(OsStr::new)
            .chain(location.suffix.iter().map(OsString::as_os_str))
            .enumerate()
        {
            let inside = index + 1 >= prefix.len();
            let child = match open_at(&parent, name, true) {
                Ok(child) => child,
                Err(error) if create && inside && error.kind() == io::ErrorKind::NotFound => {
                    let name_c =
                        CString::new(name.as_bytes()).map_err(|_| denied("invalid_component"))?;
                    let result =
                        unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) };
                    if result != 0
                        && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                    {
                        return Err(io::Error::last_os_error());
                    }
                    open_at(&parent, name, true)?
                }
                Err(error) => return Err(error),
            };
            owned(&child, caller, inside)?;
            if inside {
                app.push(child.try_clone()?);
            }
            parent = child;
        }
        Ok(app)
    }

    fn regular(file: &File, caller: &Caller) -> io::Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(denied("not_single_link_regular_file"));
        }
        owned(file, caller, true)
    }

    fn optional_file(parent: &File, name: &str, caller: &Caller) -> io::Result<Option<File>> {
        match open_at(parent, OsStr::new(name), false) {
            Ok(file) => {
                regular(&file, caller)?;
                Ok(Some(file))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn lock_namespace(
        parent: &File,
        caller: &Caller,
        held: &mut Vec<NamespaceLock>,
    ) -> io::Result<()> {
        for name in ["p2wlan-daemon.diag-auth.lock", "p2wlan-config.json.lock"] {
            let file = optional_file(parent, name, caller)?;
            if let Some(file) = file.as_ref() {
                fs2::FileExt::try_lock_exclusive(file)
                    .map_err(|_| denied("runtime_namespace_busy"))?;
            }
            held.push(NamespaceLock {
                directory: parent.try_clone()?,
                name,
                held: file,
            });
        }
        Ok(())
    }

    fn restore_permissions(file: &File, caller: &Caller, mode: libc::mode_t) -> io::Result<()> {
        owned(file, caller, true)?;
        let metadata = file.metadata()?;
        if (metadata.uid() != caller.uid || metadata.gid() != caller.gid)
            && unsafe { libc::fchown(file.as_raw_fd(), caller.uid, caller.gid) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn prepare(caller: &Caller, path: &Path) -> io::Result<()> {
        let location = location(caller, path)?;
        let home = open_home(caller)?;
        let directories = open_app(caller, &home, &location, true)?;
        let leaf = directories
            .last()
            .ok_or_else(|| denied("missing_app_directory"))?;
        let mut locks = Vec::new();
        lock_namespace(leaf, caller, &mut locks)?;

        // Account configs share the main log namespace; room hashes identify
        // both sides. The GUI stops its old daemon before invoking this helper.
        // Missing locks are never created, and other account trees are not scanned.
        let other = Location {
            kind: if location.kind == DirectoryKind::Config {
                DirectoryKind::Logs
            } else {
                DirectoryKind::Config
            },
            suffix: if location.suffix.first().is_some_and(|name| name == "rooms") {
                location.suffix.clone()
            } else {
                Vec::new()
            },
        };
        match open_app(caller, &home, &other, false) {
            Ok(other) => {
                if let Some(leaf) = other.last() {
                    lock_namespace(leaf, caller, &mut locks)?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let names: &[&str] = match location.kind {
            DirectoryKind::Config => &["p2wlan-config.json"],
            DirectoryKind::Logs => &[
                "p2wlan-daemon.log",
                "p2wlan-daemon.log.1",
                "p2wlan-daemon.pid",
            ],
        };
        let mut files = Vec::new();
        for name in names {
            if let Some(file) = optional_file(leaf, name, caller)? {
                files.push(file);
            }
        }
        // All existing leaves and namespace locks have been checked before any
        // existing owner/mode changes. Fixed FDs prevent symlink replacement.
        for lock in &locks {
            lock.verify_current(caller)?;
        }
        for directory in &directories {
            restore_permissions(directory, caller, 0o700)?;
        }
        for file in &files {
            regular(file, caller)?;
            restore_permissions(file, caller, 0o600)?;
        }
        Ok(())
    }

    pub(super) fn run(path: &Path) -> io::Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(denied("root_required"));
        }
        let sudo = std::env::var_os("SUDO_UID");
        let pkexec = std::env::var_os("PKEXEC_UID");
        let uid = caller_uid(sudo.as_deref(), pkexec.as_deref())?;
        prepare(&lookup_caller(uid)?, path)
    }

    #[cfg(test)]
    pub(super) fn prepare_for_test(
        uid: libc::uid_t,
        gid: libc::gid_t,
        home: PathBuf,
        path: &Path,
    ) -> io::Result<()> {
        prepare(&Caller { uid, gid, home }, path)
    }

    #[cfg(test)]
    pub(super) fn caller_uid_for_test(
        sudo: Option<&OsStr>,
        pkexec: Option<&OsStr>,
    ) -> io::Result<libc::uid_t> {
        caller_uid(sudo, pkexec)
    }
}
