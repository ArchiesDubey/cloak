//! Security primitives: process hardening, memory zeroization, and anti-dump safeguards.

use zeroize::Zeroize;

/// Disable core dumps for the running process to prevent secrets in memory
/// from being dumped to disk if the process crashes or receives SIGSEGV/SIGQUIT.
pub fn harden_process() {
    #[cfg(unix)]
    unsafe {
        // Set RLIMIT_CORE to 0
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim);

        #[cfg(target_os = "linux")]
        {
            // Disallow ptrace attachment by non-root processes
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
}

/// A wrapper around a vector of bytes that guarantees zeroization on drop.
#[allow(dead_code)]
#[derive(Clone)]
pub struct ProtectedBuffer(pub Vec<u8>);

impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl AsRef<[u8]> for ProtectedBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
