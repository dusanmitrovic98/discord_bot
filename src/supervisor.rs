//! # Linux Sealed Memory Process Supervisor & Watchdog
//!
//! Executes child cores in anonymous RAM using Linux `memfd_create`.
//! Bridges child stdout and stderr into the supervisor's telemetry buffer.

use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use crate::telemetry::LogBuffer;
use crate::{AegisError, Result};

pub struct MemoryExecutable {
    pub fd: RawFd,
}

impl MemoryExecutable {
    #[cfg(target_os = "linux")]
    pub fn create_sealed(name: &str, binary_data: &[u8]) -> Result<Self> {
        unsafe {
            let c_name =
                CString::new(name).map_err(|e| AegisError::SupervisorError(e.to_string()))?;
            let fd =
                libc::memfd_create(c_name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING);
            if fd < 0 {
                return Err(AegisError::SupervisorError(
                    "libc::memfd_create failed".into(),
                ));
            }

            let mut file = File::from_raw_fd(fd);
            file.write_all(binary_data)?;
            file.flush()?;
            let _ = file.into_raw_fd();

            if libc::fchmod(fd, 0o755) < 0 {
                libc::close(fd);
                return Err(AegisError::SupervisorError(
                    "fchmod 0755 failed on memfd".into(),
                ));
            }

            let seals =
                libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
            if libc::fcntl(fd, libc::F_ADD_SEALS, seals) < 0 {
                libc::close(fd);
                return Err(AegisError::SupervisorError(
                    "Applying seals failed on memfd".into(),
                ));
            }

            Ok(Self { fd })
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create_sealed(_name: &str, _binary_data: &[u8]) -> Result<Self> {
        Ok(Self { fd: -1 })
    }

    /// Spawns the child core with piped stdout and stderr to capture telemetry
    pub fn spawn_child(&self) -> Result<Child> {
        #[cfg(target_os = "linux")]
        {
            let proc_path = format!("/proc/self/fd/{}", self.fd);
            Command::new(proc_path)
                .env("AEGIS_CHILD_MODE", "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| AegisError::SupervisorError(format!("Failed executing memfd: {}", e)))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(AegisError::SupervisorError(
                "memfd direct execution requires Linux".into(),
            ))
        }
    }
}

pub struct SupervisorWatchdog {
    current_child: Option<Child>,
    lkg_blob: Option<Vec<u8>>,
    log_buffer: LogBuffer,
}

impl SupervisorWatchdog {
    pub fn new(log_buffer: LogBuffer) -> Self {
        Self {
            current_child: None,
            lkg_blob: None,
            log_buffer,
        }
    }

    fn attach_child_pipes(child: &mut Child, log_buffer: LogBuffer) {
        if let Some(stdout) = child.stdout.take() {
            let buf = log_buffer.clone();
            std::thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines().flatten() {
                    println!("{}", line);
                    buf.push_raw_line(&line);
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let buf = log_buffer;
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines().flatten() {
                    eprintln!("{}", line);
                    buf.push_raw_line(&line);
                }
            });
        }
    }

    fn probe_child_health(child: &mut Child, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            match child.try_wait() {
                Ok(Some(status)) => {
                    error!("Child crashed prematurely with status: {}", status);
                    return false;
                }
                Ok(None) => {}
                Err(e) => {
                    error!("Error monitoring child: {}", e);
                    return false;
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        true
    }

    fn rollback_to_lkg(&mut self) -> Result<()> {
        warn!("Watchdog triggered rollback to Last Known Good binary!");
        let lkg = self.lkg_blob.as_ref().ok_or_else(|| {
            AegisError::SupervisorError("Fatal: New version crashed, no LKG available".into())
        })?;

        let fallback = MemoryExecutable::create_sealed("aegis_core_lkg", lkg)?;
        let mut child = fallback.spawn_child()?;
        Self::attach_child_pipes(&mut child, self.log_buffer.clone());
        self.current_child = Some(child);
        Err(AegisError::SupervisorError(
            "New version crashed; rolled back to LKG".into(),
        ))
    }

    fn reap_child_gracefully(mut old_child: Child) {
        let pid = old_child.id() as i32;
        info!("Sending SIGTERM to previous core process (PID: {})...", pid);

        #[cfg(target_os = "linux")]
        unsafe {
            let _ = libc::kill(pid, libc::SIGTERM);
        }

        let start = Instant::now();
        let timeout = Duration::from_secs(3);
        let mut exited = false;

        while start.elapsed() < timeout {
            if let Ok(Some(_)) = old_child.try_wait() {
                exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        if !exited {
            warn!(
                "Process PID {} did not exit within 3s. Issuing fallback SIGKILL.",
                pid
            );
            let _ = old_child.kill();
            let _ = old_child.wait();
        } else {
            info!("Process PID {} terminated gracefully.", pid);
        }
    }

    pub fn hot_swap_core(&mut self, new_binary: Vec<u8>) -> Result<()> {
        info!("Initiating in-memory core swap...");

        let mem_exec = MemoryExecutable::create_sealed("aegis_core_swapped", &new_binary)?;
        let mut new_child = mem_exec.spawn_child()?;

        // Immediately attach pipes so all startup logs are captured in RAM!
        Self::attach_child_pipes(&mut new_child, self.log_buffer.clone());

        if !Self::probe_child_health(&mut new_child, Duration::from_secs(5)) {
            return self.rollback_to_lkg();
        }

        if let Some(old_child) = self.current_child.take() {
            Self::reap_child_gracefully(old_child);
        }

        self.lkg_blob = Some(new_binary);
        self.current_child = Some(new_child);
        info!("Core swap verified healthy. Child is running in sealed RAM.");

        Ok(())
    }
}
