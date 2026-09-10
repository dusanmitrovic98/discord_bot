use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

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
            let _ = file.into_raw_fd(); // Prevent Drop from closing fd

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

    pub fn spawn_child(&self) -> Result<Child> {
        #[cfg(target_os = "linux")]
        {
            let proc_path = format!("/proc/self/fd/{}", self.fd);
            Command::new(proc_path)
                .env("AEGIS_CHILD_MODE", "1")
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
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
}

impl Default for SupervisorWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

impl SupervisorWatchdog {
    pub fn new() -> Self {
        Self {
            current_child: None,
            lkg_blob: None,
        }
    }

    /// Pure watchdog probe: Polls child health over duration (NASA Rule 4)
    fn probe_child_health(child: &mut Child, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            match child.try_wait() {
                Ok(Some(status)) => {
                    error!("Child crashed prematurely with exit status: {}", status);
                    return false;
                }
                Ok(None) => {}
                Err(e) => {
                    error!("Error monitoring child process: {}", e);
                    return false;
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        true
    }

    /// Re-spawns the Last Known Good cached binary upon failure
    fn rollback_to_lkg(&mut self) -> Result<()> {
        warn!("Watchdog triggered rollback to Last Known Good binary!");
        let lkg = self.lkg_blob.as_ref().ok_or_else(|| {
            AegisError::SupervisorError("Fatal: New version crashed and no LKG available".into())
        })?;

        let fallback = MemoryExecutable::create_sealed("aegis_core_lkg", lkg)?;
        self.current_child = Some(fallback.spawn_child()?);
        Err(AegisError::SupervisorError(
            "New version crashed; rolled back to LKG".into(),
        ))
    }

    /// Gracefully reaps an existing child process
    fn reap_child(mut old_child: Child) {
        info!(
            "Terminating previous core process (PID: {})...",
            old_child.id()
        );
        let _ = old_child.kill();
        let _ = old_child.wait();
    }

    /// Linear, readable hot-swap state machine (<20 lines, NASA Rule 1)
    pub fn hot_swap_core(&mut self, new_binary: Vec<u8>) -> Result<()> {
        info!("Initiating in-memory core swap...");

        let mem_exec = MemoryExecutable::create_sealed("aegis_core_swapped", &new_binary)?;
        let mut new_child = mem_exec.spawn_child()?;

        if !Self::probe_child_health(&mut new_child, Duration::from_secs(5)) {
            return self.rollback_to_lkg();
        }

        if let Some(old_child) = self.current_child.take() {
            Self::reap_child(old_child);
        }

        self.lkg_blob = Some(new_binary);
        self.current_child = Some(new_child);
        info!("Core swap verified healthy. Child is running in sealed RAM.");

        Ok(())
    }
}
