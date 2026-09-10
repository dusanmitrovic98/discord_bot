use crate::{AegisError, Result};
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

pub struct MemoryExecutable {
    pub fd: RawFd,
}

impl MemoryExecutable {
    /// Allocates an anonymous in-memory file descriptor and loads binary bytes directly to RAM.
    #[cfg(target_os = "linux")]
    pub fn create_sealed(name: &str, binary_data: &[u8]) -> Result<Self> {
        unsafe {
            let c_name =
                CString::new(name).map_err(|e| AegisError::SupervisorError(e.to_string()))?;

            // MFD_CLOEXEC | MFD_ALLOW_SEALING
            let fd =
                libc::memfd_create(c_name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING);
            if fd < 0 {
                return Err(AegisError::SupervisorError(
                    "libc::memfd_create syscall failed".into(),
                ));
            }

            // Write binary into RAM
            let mut file = File::from_raw_fd(fd);
            file.write_all(binary_data)?;
            file.flush()?;

            // CRUCIAL: Disown the File struct so its Drop handler does NOT close our fd!
            let _ = file.into_raw_fd();

            // Set execution permissions on the in-memory descriptor
            if libc::fchmod(fd, 0o755) < 0 {
                libc::close(fd);
                return Err(AegisError::SupervisorError(
                    "Failed setting chmod 0755 on memfd".into(),
                ));
            }

            // Apply immutable seals: Prevent write, shrink, grow, or seal mutation
            let seals =
                libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
            if libc::fcntl(fd, libc::F_ADD_SEALS, seals) < 0 {
                libc::close(fd);
                return Err(AegisError::SupervisorError(
                    "Failed applying memory seals to memfd".into(),
                ));
            }

            Ok(Self { fd })
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create_sealed(_name: &str, _binary_data: &[u8]) -> Result<Self> {
        Ok(Self { fd: -1 })
    }

    /// Spawns the child process directly from `/proc/self/fd/<fd>`, inheriting stdout/stderr.
    pub fn spawn_child(&self) -> Result<Child> {
        #[cfg(target_os = "linux")]
        {
            let proc_path = format!("/proc/self/fd/{}", self.fd);
            Command::new(proc_path)
                .env("AEGIS_CHILD_MODE", "1")
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| {
                    AegisError::SupervisorError(format!("Failed executing memfd binary: {}", e))
                })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(AegisError::SupervisorError(
                "memfd direct execution is strictly supported on Linux".into(),
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

    pub fn hot_swap_core(&mut self, new_binary: Vec<u8>) -> Result<()> {
        info!("Initiating in-memory core swap...");

        let mem_exec = MemoryExecutable::create_sealed("aegis_core_swapped", &new_binary)?;
        let mut new_child = mem_exec.spawn_child()?;

        // Watchdog loop: Assert child survives boot
        let start = Instant::now();
        let timeout = Duration::from_secs(5);
        let mut healthy = true;

        while start.elapsed() < timeout {
            match new_child.try_wait() {
                Ok(Some(status)) => {
                    error!("New core crashed prematurely with exit status: {}", status);
                    healthy = false;
                    break;
                }
                Ok(None) => {}
                Err(e) => {
                    error!("Error monitoring child process: {}", e);
                    healthy = false;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        if !healthy {
            warn!("Watchdog triggered rollback!");
            if let Some(lkg) = &self.lkg_blob {
                let fallback = MemoryExecutable::create_sealed("aegis_core_lkg", lkg)?;
                self.current_child = Some(fallback.spawn_child()?);
                return Err(AegisError::SupervisorError(
                    "New version crashed; rolled back to LKG".into(),
                ));
            } else {
                return Err(AegisError::SupervisorError(
                    "Fatal: New version crashed and no LKG available".into(),
                ));
            }
        }

        // Gracefully kill previous child if one was running
        if let Some(mut old_child) = self.current_child.take() {
            info!(
                "Terminating previous core process (PID: {})...",
                old_child.id()
            );
            let _ = old_child.kill();
            let _ = old_child.wait();
        }

        self.lkg_blob = Some(new_binary);
        self.current_child = Some(new_child);
        info!("Core swap verified healthy. Child is running in sealed RAM.");

        Ok(())
    }
}
