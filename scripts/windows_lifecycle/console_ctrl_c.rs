//! A single console broadcast, compiled before the bounded acceptance cycle.
//! Build directly with rustc; no Cargo dependency or script runtime is needed.
#[cfg(any(windows, test))]
mod records {
    use std::{ffi::OsString, fs::OpenOptions, io::Write, path::PathBuf, time::Instant};

    pub struct Request {
        pub pid: u32,
        pub id: String,
        pub evidence: PathBuf,
        pub diagnostic: Option<PathBuf>,
    }

    impl Request {
        pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, &'static str> {
            let mut pid = None;
            let mut id = None;
            let mut evidence = None;
            let mut diagnostic = None;
            let mut args = args.into_iter();
            while let Some(flag) = args.next() {
                let value = args.next().ok_or("missing_argument")?;
                match flag.to_str() {
                    Some("-ProcessId") if pid.is_none() => {
                        let value: u32 = value
                            .to_str()
                            .ok_or("invalid_pid")?
                            .parse()
                            .map_err(|_| "invalid_pid")?;
                        if value == 0 || value > i32::MAX as u32 {
                            return Err("invalid_pid");
                        }
                        pid = Some(value);
                    }
                    Some("-RequestId") if id.is_none() => {
                        let value = value.into_string().map_err(|_| "invalid_request")?;
                        if value.len() != 32
                            || !value
                                .bytes()
                                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                        {
                            return Err("invalid_request");
                        }
                        id = Some(value);
                    }
                    Some("-EvidencePath") if evidence.is_none() && !value.is_empty() => {
                        evidence = Some(PathBuf::from(value))
                    }
                    Some("-DiagnosticDirectory") if diagnostic.is_none() && !value.is_empty() => {
                        diagnostic = Some(PathBuf::from(value))
                    }
                    _ => return Err("unknown_or_duplicate_argument"),
                }
            }
            let evidence = evidence.ok_or("missing_evidence")?;
            if let Some(path) = &diagnostic {
                let mut expected = evidence.as_os_str().to_os_string();
                expected.push(".diagnostic");
                if path != &PathBuf::from(expected) {
                    return Err("diagnostic_path_mismatch");
                }
            }
            Ok(Self {
                pid: pid.ok_or("missing_pid")?,
                id: id.ok_or("missing_request")?,
                evidence,
                diagnostic,
            })
        }
    }

    pub struct Record {
        pub request: Request,
        pub stage: &'static str,
        pub succeeded: bool,
        pub error: Option<u32>,
        started: Instant,
        sequence: u32,
    }

    fn write_new(path: &std::path::Path, text: &str) -> std::io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(text.as_bytes())
    }

    impl Record {
        pub fn new(request: Request) -> Self {
            Self {
                request,
                stage: "initialize",
                succeeded: false,
                error: None,
                started: Instant::now(),
                sequence: 0,
            }
        }

        pub fn phase(&mut self, phase: &'static str) {
            let Some(directory) = self.request.diagnostic.as_ref() else {
                return;
            };
            self.sequence += 1;
            if self.sequence > 12 {
                self.request.diagnostic = None;
                return;
            }
            let text = format!("{{\"schema_version\":1,\"request_id\":\"{}\",\"target_process_id\":{},\"helper_process_id\":{},\"sequence\":{},\"phase\":\"{}\",\"native_stage\":\"{}\",\"elapsed_monotonic_ticks\":{},\"monotonic_frequency_hz\":1000000000,\"broadcast_succeeded\":{}}}\n",
                self.request.id, self.request.pid, std::process::id(), self.sequence, phase, self.stage, self.started.elapsed().as_nanos(), self.succeeded);
            let path = directory.join(format!("phase-{:02}-{phase}.json", self.sequence));
            if text.len() > 2048 || write_new(&path, &text).is_err() {
                // Missing diagnostics stay unknown; they never change a native return.
                self.request.diagnostic = None;
            }
        }

        pub fn finish(&mut self) -> std::io::Result<()> {
            self.phase("write_native_evidence");
            let error = self
                .error
                .map_or_else(|| "null".to_owned(), |e| e.to_string());
            let detail = if self.error.is_some() {
                "native_console_api_failed"
            } else {
                ""
            };
            let text = format!("{{\"request_id\":\"{}\",\"target_process_id\":{},\"broadcast_succeeded\":{},\"stage\":\"{}\",\"native_error_code\":{},\"detail\":\"{}\"}}\n",
                self.request.id, self.request.pid, self.succeeded, self.stage, error, detail);
            write_new(&self.request.evidence, &text)?;
            self.phase("native_evidence_written");
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs,
            sync::atomic::{AtomicUsize, Ordering},
        };

        fn args() -> Vec<OsString> {
            [
                "-ProcessId",
                "123",
                "-RequestId",
                "0123456789abcdef0123456789abcdef",
                "-EvidencePath",
                "evidence.json",
            ]
            .map(OsString::from)
            .to_vec()
        }

        #[test]
        fn arguments_reject_duplicate_negative_missing_and_invalid_identity() {
            assert_eq!(Request::parse(args()).unwrap().pid, 123);
            for values in [
                vec!["-ProcessId", "0"],
                vec!["-ProcessId", "-1"],
                vec!["-ProcessId", "2147483648"],
                vec!["-RequestId", "bad"],
                vec!["-ProcessId"],
            ] {
                assert!(Request::parse(values.into_iter().map(OsString::from)).is_err());
            }
            let mut duplicate = args();
            duplicate.extend([OsString::from("-ProcessId"), OsString::from("123")]);
            assert!(Request::parse(duplicate).is_err());
            let mut wrong_path = args();
            wrong_path.extend([
                OsString::from("-DiagnosticDirectory"),
                OsString::from("foreign"),
            ]);
            assert!(Request::parse(wrong_path).is_err());
        }

        #[test]
        fn records_are_bounded_exclusive_and_preserve_native_failure() {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "p2wlan-native-record-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            let evidence = path.join("evidence.json");
            let directory = path.join("evidence.json.diagnostic");
            fs::create_dir(&directory).unwrap();
            let mut record = Record::new(Request {
                pid: 123,
                id: "0123456789abcdef0123456789abcdef".into(),
                evidence: evidence.clone(),
                diagnostic: Some(directory.clone()),
            });
            record.phase("initialize");
            record.stage = "attach_console";
            record.error = Some(6);
            record.phase("caught_exception");
            record.finish().unwrap();
            let original = fs::read(&evidence).unwrap();
            assert!(String::from_utf8_lossy(&original).contains("\"broadcast_succeeded\":false"));
            assert!(String::from_utf8_lossy(&original).contains("\"native_error_code\":6"));
            assert!(record.finish().is_err());
            assert_eq!(fs::read(&evidence).unwrap(), original);
            for _ in 0..20 {
                record.phase("initialize");
            }
            let entries: Vec<_> = fs::read_dir(&directory)
                .unwrap()
                .map(|x| x.unwrap().metadata().unwrap().len())
                .collect();
            assert!(entries.len() <= 12 && entries.iter().all(|n| *n <= 2048));
            fs::remove_dir_all(path).unwrap();
        }
    }
}

#[cfg(windows)]
fn main() {
    use records::{Record, Request};
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn FreeConsole() -> i32;
        fn AttachConsole(pid: u32) -> i32;
        fn SetConsoleCtrlHandler(handler: *const std::ffi::c_void, add: i32) -> i32;
        fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
        fn GetLastError() -> u32;
    }
    let request = match Request::parse(std::env::args_os().skip(1)) {
        Ok(request) => request,
        Err(reason) => {
            eprintln!("{reason}");
            std::process::exit(2);
        }
    };
    let mut record = Record::new(request);
    record.phase("initialize");
    record.phase("native_helper_ready");
    record.stage = "attach_console";
    record.phase("attach_console");
    unsafe {
        FreeConsole();
        if AttachConsole(record.request.pid) == 0 {
            record.error = Some(GetLastError());
        } else {
            record.phase("attached_console");
            record.stage = "protect_injector";
            record.phase("protect_injector");
            if SetConsoleCtrlHandler(std::ptr::null(), 1) == 0 {
                record.error = Some(GetLastError());
            } else {
                record.phase("protected_injector");
                record.stage = "broadcast_ctrl_c";
                record.phase("broadcast_ctrl_c");
                if GenerateConsoleCtrlEvent(0, 0) == 0 {
                    record.error = Some(GetLastError());
                } else {
                    record.succeeded = true;
                    record.phase("broadcast_succeeded");
                }
            }
        }
    }
    if record.error.is_some() {
        record.phase("caught_exception");
    }
    // Keep the ignore attribute until process exit, including a pending self
    // broadcast. FreeConsole here would reset the handler table too early.
    let code = if record.finish().is_ok() && record.succeeded {
        0
    } else {
        1
    };
    std::process::exit(code);
}

#[cfg(not(windows))]
fn main() {
    eprintln!("requires native Windows console API");
    std::process::exit(78);
}
