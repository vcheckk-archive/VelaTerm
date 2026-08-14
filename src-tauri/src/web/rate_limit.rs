//! Login rate limiting and Argon2 verification throttling for the unauthenticated surface.
//!
//! `POST /api/login` and the WebSocket E2EE handshake both verify an Argon2id password and are reachable
//! without credentials, so they form a DoS-amplification primitive: each request costs the server a
//! memory-hard hash. Two independent brakes contain that:
//!
//! - [`LoginRateLimiter`]: a per-IP fixed window of login attempts. A blocked IP is rejected before any
//!   Argon2 work happens. The limiter is in-memory by design — a restart resets it, which is acceptable
//!   because the pairing token plus Argon2 remain as the actual credential barrier. One limiter is
//!   shared per data directory across every in-process server instance (see [`LoginRateLimiter::shared`],
//!   the `PAIRING_STORES` pattern from auth.rs), so a dual-instance `--serve` setup no longer doubles an
//!   attacker's budget. [`allow`](LoginRateLimiter::allow) *reserves* an attempt atomically, so N
//!   parallel requests from one IP cannot slip under the limit before any of them records a failure.
//! - [`VERIFY_SEMAPHORE`]: a process-wide cap on concurrent Argon2 verifications, combined with
//!   `spawn_blocking` in `AuthState::verify_password_async` so the async executor is never blocked.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
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

/// Per-IP login-attempt window. All mutating accesses prune expired entries so the map cannot grow
/// unboundedly under a spread of source addresses.
pub struct LoginRateLimiter {
    entries: Mutex<HashMap<IpAddr, WindowEntry>>,
}

struct WindowEntry {
    window_start: Instant,
    /// Completed failed attempts within this window.
    failures: u32,
    /// Attempts reserved by [`LoginRateLimiter::allow`] whose outcome is still pending. Counted
    /// against the limit so parallel requests from one IP cannot all pass the check before the
    /// first failure is recorded (TOCTOU). A failure converts a reservation into a failure; a
    /// success removes the whole entry.
    pending: u32,
}

/// Process-wide registry of live limiters keyed by canonicalized data directory (the `PAIRING_STORES`
/// pattern). Weak entries let a limiter die with its last server instance; sister instances serving the
/// same data directory share one budget instead of multiplying it.
static LOGIN_LIMITERS: OnceLock<Mutex<HashMap<PathBuf, Weak<LoginRateLimiter>>>> = OnceLock::new();

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Shared limiter for one data directory: every in-process server instance over the same directory
    /// (CLI `--serve` primary, auto-started secondary, GUI/Electron) gets the same limiter, so an
    /// attacker cannot multiply the per-IP budget by the number of instances.
    pub fn shared(data_dir: &Path) -> Arc<Self> {
        // Canonicalize so `/tmp/x` and `/private/tmp/x` (macOS) resolve to the same limiter; fall back
        // to the raw path when the directory cannot be resolved.
        let key = data_dir
            .canonicalize()
            .unwrap_or_else(|_| data_dir.to_path_buf());
        let registry = LOGIN_LIMITERS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut map = registry.lock().unwrap();
        // Prune dead entries so the map does not accumulate one Weak per finished server lifetime.
        map.retain(|_, w| w.strong_count() > 0);
        if let Some(existing) = map.get(&key).and_then(Weak::upgrade) {
            return existing;
        }
        let limiter = Arc::new(Self::new());
        map.insert(key, Arc::downgrade(&limiter));
        limiter
    }

    /// Whether this IP may attempt a login now. A `true` result **reserves** one attempt against the
    /// window immediately, so it must be paired with exactly one `record_failure` or `record_success`.
    pub fn allow(&self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    /// Record a failed login attempt for this IP, converting its pending reservation into a failure.
    pub fn record_failure(&self, ip: IpAddr) {
        self.record_failure_at(ip, Instant::now());
    }

    /// Clear the attempt counter after a successful login: a legitimate user who mistyped a few times
    /// must not carry the penalty into the next window.
    pub fn record_success(&self, ip: IpAddr) {
        let mut entries = self.entries.lock().unwrap();
        entries.remove(&ip);
    }

    /// Time-injectable core of [`allow`], used by tests to step through window expiry.
    fn allow_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut entries = self.entries.lock().unwrap();
        prune(&mut entries, now);
        let e = entries.entry(ip).or_insert(WindowEntry {
            window_start: now,
            failures: 0,
            pending: 0,
        });
        if e.failures.saturating_add(e.pending) >= MAX_FAILURES {
            return false;
        }
        e.pending = e.pending.saturating_add(1);
        true
    }

    /// Time-injectable core of [`record_failure`].
    fn record_failure_at(&self, ip: IpAddr, now: Instant) {
        let mut entries = self.entries.lock().unwrap();
        prune(&mut entries, now);
        let e = entries.entry(ip).or_insert(WindowEntry {
            window_start: now,
            failures: 0,
            pending: 0,
        });
        e.pending = e.pending.saturating_sub(1);
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
        // Any access after the window prunes every expired entry; only the fresh reservation that
        // this allow itself creates remains.
        assert!(l.allow_at(ip(1), t0 + WINDOW));
        assert_eq!(l.entries.lock().unwrap().len(), 1);
    }

    /// TOCTOU regression: `allow` reserves the attempt, so MAX_FAILURES parallel requests from one IP
    /// exhaust the budget even before any of them records its failure.
    #[test]
    fn parallel_reservations_cannot_undercut_the_limit() {
        let l = LoginRateLimiter::new();
        let t0 = Instant::now();
        // Simulate N in-flight requests: all call allow before any outcome is recorded.
        for _ in 0..MAX_FAILURES {
            assert!(l.allow_at(ip(1), t0));
        }
        // Attempt N+1 is rejected although zero failures have been recorded yet.
        assert!(!l.allow_at(ip(1), t0));
        // The in-flight requests now fail; the budget stays exhausted, not doubled.
        for _ in 0..MAX_FAILURES {
            l.record_failure_at(ip(1), t0);
        }
        assert!(!l.allow_at(ip(1), t0));
        // Reservations expire with the window like failures do.
        assert!(l.allow_at(ip(1), t0 + WINDOW));
    }

    /// A success releases the reservation and clears the counter, so a legitimate login within the
    /// budget never blocks the next attempt.
    #[test]
    fn success_releases_the_reservation() {
        let l = LoginRateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..MAX_FAILURES {
            assert!(l.allow_at(ip(1), t0));
            l.record_success(ip(1));
        }
        assert!(l.allow_at(ip(1), t0));
    }

    /// Dual-instance fix: two server instances over the same data directory share ONE limiter, so an
    /// attacker gets one budget, not one per instance. Different directories stay independent, and the
    /// registry is Weak: once the last instance drops its Arc, a later instance gets a fresh limiter.
    #[test]
    fn limiter_is_shared_per_data_dir() {
        let dir_a = std::env::temp_dir().join(format!(
            "vlx-rl-a-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let dir_b = std::env::temp_dir().join(format!(
            "vlx-rl-b-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();

        let first = LoginRateLimiter::shared(&dir_a);
        let second = LoginRateLimiter::shared(&dir_a);
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "instances over the same data dir must share one limiter"
        );

        // Exhaust the budget through the first handle; the second handle sees the block immediately.
        let t0 = Instant::now();
        for _ in 0..MAX_FAILURES {
            assert!(first.allow_at(ip(9), t0));
            first.record_failure_at(ip(9), t0);
        }
        assert!(!second.allow_at(ip(9), t0), "5x5 dual-instance budget must be closed");

        // An unrelated data dir gets its own limiter and budget.
        let other = LoginRateLimiter::shared(&dir_b);
        assert!(!std::sync::Arc::ptr_eq(&first, &other));
        assert!(other.allow_at(ip(9), t0));

        // Weak registry: dropping every Arc lets the limiter die; the next shared() starts fresh.
        drop(first);
        drop(second);
        let revived = LoginRateLimiter::shared(&dir_a);
        assert!(revived.allow_at(ip(9), t0), "a revived limiter starts with an empty window");

        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }
}
