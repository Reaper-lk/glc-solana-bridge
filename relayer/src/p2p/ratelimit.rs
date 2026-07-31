//! Per-peer request rate limiting for the signer service (Phase 7d).
//!
//! [`super::policy::Refusal::RateLimited`] has existed since Phase 7c but was
//! never enforced. This module enforces it.
//!
//! # Why a signer needs one at all
//!
//! Signing is the expensive path: [`super::policy::evaluate`] re-derives the
//! canonical message from this validator's own persisted chain observations,
//! which means a database transaction per request. mTLS bounds *who* can
//! ask, but a single authenticated peer — buggy, or compromised — can still
//! ask without limit, and a signer that is busy re-deriving cannot answer
//! the peers that need it. The point is availability of the signing service,
//! not secrecy: nothing here protects a key, it protects the ability to
//! answer.
//!
//! # Per peer, not global
//!
//! Buckets are keyed independently, so one noisy peer exhausts only its own
//! allowance. A global limit would let any single peer deny service to the
//! whole federation, which is precisely the failure this is meant to
//! prevent.
//!
//! Timekeeping is injected rather than read from the clock, so the refill
//! behaviour is tested deterministically instead of with sleeps.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Sustained requests per second allowed to each peer.
///
/// Generous relative to honest load: a peer asks roughly once per deposit
/// per tick, and ticks are seconds apart. The limit exists to bound abuse,
/// not to pace correct behaviour.
pub const REFILL_PER_SECOND: f64 = 10.0;

/// How many requests a peer may make back-to-back before the sustained rate
/// applies.
///
/// A burst allowance is required, not a nicety: a relayer catching up after
/// a restart legitimately asks about every pending deposit at once, and
/// throttling that would turn a recovery into a stall.
pub const BURST: f64 = 30.0;

/// A token bucket per peer.
pub struct RateLimiter {
    refill_per_second: f64,
    burst: f64,
    buckets: HashMap<String, Bucket>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::with_limits(REFILL_PER_SECOND, BURST)
    }

    pub fn with_limits(refill_per_second: f64, burst: f64) -> Self {
        RateLimiter {
            refill_per_second,
            burst,
            buckets: HashMap::new(),
        }
    }

    /// Charges one request against `peer`, returning whether it is allowed.
    ///
    /// `now` is passed in so the refill is deterministic under test.
    pub fn check_at(&mut self, peer: &str, now: Instant) -> bool {
        let refill = self.refill_per_second;
        let burst = self.burst;
        let bucket = self.buckets.entry(peer.to_string()).or_insert(Bucket {
            tokens: burst,
            last: now,
        });

        // `saturating_duration_since`: a non-monotonic or reordered `now`
        // must not credit tokens, which would make the limit bypassable by
        // whatever influences the clock.
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill).min(burst);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn check(&mut self, peer: &str) -> bool {
        self.check_at(peer, Instant::now())
    }

    /// Drops buckets that have been idle long enough to have fully refilled.
    ///
    /// Without this the map grows once per distinct peer key seen, which is
    /// a slow memory leak in a process meant to run for months. A fully
    /// refilled bucket is indistinguishable from a fresh one, so forgetting
    /// it grants nothing.
    pub fn evict_idle(&mut self, now: Instant, idle: Duration) {
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.last) < idle);
    }

    pub fn tracked_peers(&self) -> usize {
        self.buckets.len()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_a_burst_then_refuses() {
        let mut rl = RateLimiter::with_limits(10.0, 3.0);
        let t = Instant::now();
        assert!(rl.check_at("a", t));
        assert!(rl.check_at("a", t));
        assert!(rl.check_at("a", t));
        assert!(
            !rl.check_at("a", t),
            "the burst allowance must be finite, or the limit is not a limit"
        );
    }

    #[test]
    fn refills_over_time() {
        let mut rl = RateLimiter::with_limits(10.0, 2.0);
        let t = Instant::now();
        assert!(rl.check_at("a", t));
        assert!(rl.check_at("a", t));
        assert!(!rl.check_at("a", t));
        // 10/s means one token back after 100ms.
        assert!(rl.check_at("a", t + Duration::from_millis(100)));
    }

    #[test]
    fn refill_is_capped_at_the_burst_size() {
        // An hour idle must not bank an hour's worth of requests.
        let mut rl = RateLimiter::with_limits(10.0, 2.0);
        let t = Instant::now();
        assert!(rl.check_at("a", t));
        let later = t + Duration::from_secs(3600);
        assert!(rl.check_at("a", later));
        assert!(rl.check_at("a", later));
        assert!(
            !rl.check_at("a", later),
            "idle time must not accumulate beyond the burst ceiling"
        );
    }

    #[test]
    fn one_peer_cannot_exhaust_anothers_allowance() {
        // The property that makes this per-peer rather than global: a noisy
        // peer must not be able to deny service to the rest of the
        // federation.
        let mut rl = RateLimiter::with_limits(10.0, 2.0);
        let t = Instant::now();
        assert!(rl.check_at("noisy", t));
        assert!(rl.check_at("noisy", t));
        assert!(!rl.check_at("noisy", t));
        assert!(rl.check_at("quiet", t), "an unrelated peer is unaffected");
        assert!(rl.check_at("quiet", t));
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_grant_tokens() {
        let mut rl = RateLimiter::with_limits(10.0, 1.0);
        let t = Instant::now() + Duration::from_secs(10);
        assert!(rl.check_at("a", t));
        assert!(
            !rl.check_at("a", t - Duration::from_secs(5)),
            "a backwards clock must not refill the bucket"
        );
    }

    #[test]
    fn idle_buckets_are_evicted_but_active_ones_are_kept() {
        let mut rl = RateLimiter::with_limits(10.0, 2.0);
        let t = Instant::now();
        rl.check_at("old", t);
        rl.check_at("recent", t + Duration::from_secs(100));
        assert_eq!(rl.tracked_peers(), 2);
        rl.evict_idle(t + Duration::from_secs(100), Duration::from_secs(60));
        assert_eq!(rl.tracked_peers(), 1, "only the idle bucket is dropped");
        assert!(rl.check_at("recent", t + Duration::from_secs(100)));
    }

    #[test]
    fn eviction_does_not_hand_back_a_spent_allowance_early() {
        // Evicting a bucket resets it, so it must only happen once the
        // bucket would have refilled anyway.
        let mut rl = RateLimiter::with_limits(1.0, 1.0);
        let t = Instant::now();
        assert!(rl.check_at("a", t));
        assert!(!rl.check_at("a", t));
        // Not yet idle enough to forget.
        rl.evict_idle(t, Duration::from_secs(60));
        assert_eq!(rl.tracked_peers(), 1);
        assert!(!rl.check_at("a", t));
    }

    #[test]
    fn the_production_defaults_permit_ordinary_catch_up_load() {
        // A restarted relayer asking about every pending deposit at once
        // must not be throttled into a stall.
        let mut rl = RateLimiter::new();
        let t = Instant::now();
        for i in 0..BURST as usize {
            assert!(rl.check_at("peer", t), "burst request {i} must be allowed");
        }
        assert!(!rl.check_at("peer", t));
    }
}
