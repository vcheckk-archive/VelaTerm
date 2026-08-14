//! Login rate limiting and Argon2 verification throttling for the unauthenticated surface.
//!
//! `POST /api/login` and the WebSocket E2EE handshake both verify an Argon2id password and are reachable
//! without credentials, so they form a DoS-amplification primitive: each request costs the server a
//! memory-hard hash. Two independent brakes contain that:
//!
//! - [`LoginRateLimiter`]: a per-IP fixed window of failed attempts. A blocked IP is rejected before any
//!   Argon2 work happens. The limiter is in-memory by design — a restart resets it, which is acceptable
//!   because the pairing token plus Argon2 remain as the actual credential barrier.
//! - [`VERIFY_SEMAPHORE`]: a process-wide cap on concurrent Argon2 verifications, combined with
//!   `spawn_blocking` in `AuthState::verify_password_async` so the async executor is never blocked.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

/// Maximum failed attempts per IP within one window before further attempts are rejected.
const MAX_FAILURES: u32 = 5;
/// Fixed window length; the failure counter of an IP resets when its window expires.
const WINDOW: Duration = Duration::from_secs(60);

/// Process-wide bound on concurrent Argon2id verifications across all server instances. Two permits keep
/// interactive logins responsive while denying an attacker the ability to saturate every blocking thread
/// with memory-hard hashing.
pub static VERIFY_SEMAPHORE: Semaphore = Semaphore::const_new(2);

/// Per-IP failed-login window. All mutating accesses prune expired entries so the map cannot grow
/// unboundedly under a spread of source addresses.
pub struct LoginRateLimiter {
    entries: Mutex<HashMap<IpAddr, WindowEntry>>,
}

struct WindowEntry {
    window_start: Instant,
    failures: u32,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Whether this IP may attempt a login now. Does not count as an attempt by itself.
    pub fn allow(&self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    /// Record a failed login attempt for this IP.
    pub fn record_failure(&self, ip: IpAddr) {
        self.record_failure_at(ip, Instant::now());
    }

    /// Clear the failure counter after a successful login: a legitimate user who mistyped a few times
    /// must not carry the penalty into the next window.
    pub fn record_success(&self, ip: IpAddr) {
        let mut entries = self.entries.lock().unwrap();
        entries.remove(&ip);
    }

    /// Time-injectable core of [`allow`], used by tests to step through window expiry.
    fn allow_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut entries = self.entries.lock().unwrap();
        prune(&mut entries, now);
        match entries.get(&ip) {
            Some(e) => e.failures < MAX_FAILURES,
            None => true,
        }
    }

    /// Time-injectable core of [`record_failure`].
    fn record_failure_at(&self, ip: IpAddr, now: Instant) {
        let mut entries = self.entries.lock().unwrap();
        prune(&mut entries, now);
        let e = entries.entry(ip).or_insert(WindowEntry {
            window_start: now,
            failures: 0,
        });
        e.failures = e.failures.saturating_add(1);
    }
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Drop entries whose window has expired; called on every access so memory stays bounded.
fn prune(entries: &mut HashMap<IpAddr, WindowEntry>, now: Instant) {
    entries.retain(|_, e| now.duration_since(e.window_start) < WINDOW);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, last))
    }

    #[test]
    fn blocks_after_max_failures_and_recovers_after_window() {
        let l = LoginRateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..MAX_FAILURES {
            assert!(l.allow_at(ip(1), t0));
            l.record_failure_at(ip(1), t0);
        }
        // The sixth attempt within the window is rejected.
        assert!(!l.allow_at(ip(1), t0));
        // Still rejected just before the window expires.
        assert!(!l.allow_at(ip(1), t0 + WINDOW - Duration::from_millis(1)));
        // Allowed again once the fixed window has passed.
        assert!(l.allow_at(ip(1), t0 + WINDOW));
    }

    #[test]
    fn success_clears_the_counter() {
        let l = LoginRateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..MAX_FAILURES {
            l.record_failure_at(ip(1), t0);
        }
        assert!(!l.allow_at(ip(1), t0));
        l.record_success(ip(1));
        assert!(l.allow_at(ip(1), t0));
    }

    #[test]
    fn ips_are_independent() {
        let l = LoginRateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..MAX_FAILURES {
            l.record_failure_at(ip(1), t0);
        }
        assert!(!l.allow_at(ip(1), t0));
        assert!(l.allow_at(ip(2), t0), "another IP must not inherit the block");
    }

    #[test]
    fn expired_entries_are_pruned_so_the_map_stays_bounded() {
        let l = LoginRateLimiter::new();
        let t0 = Instant::now();
        for last in 1..=100u8 {
            l.record_failure_at(ip(last), t0);
        }
        assert_eq!(l.entries.lock().unwrap().len(), 100);
        // Any access after the window prunes every expired entry.
        assert!(l.allow_at(ip(1), t0 + WINDOW));
        assert_eq!(l.entries.lock().unwrap().len(), 0);
    }
}
