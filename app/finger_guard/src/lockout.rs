/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Lockout related types.

use crate::error::{ServiceError, ServiceResult};
use crate::time::{Clock, Instant};
use std::time::Duration;

#[derive(thiserror::Error, Debug)]
/// LockoutStatus indicates the type of lockout and the duration of the lockout.
pub enum LockoutStatus {
    /// Permanently locked out.
    #[error("Permanent lockout")]
    Permanent,
    /// Temporary lockout with a duration.
    #[error("Timed lockout: {0:?}")]
    Timed(Duration),
    /// Unknown lockout, this usually means we could not determine the current time.
    #[error("Lockout state unknown")]
    Unknown,
}

/// Extend Result with a function that can map LockoutStatus as errors to service errors.
pub trait MapLockoutStatusErrExt<T> {
    /// Transform Self (a result with a LockoutStatus) into a ServiceResult with the given
    /// error message.
    fn wrap_lockout_status_err(self) -> ServiceResult<T>;
}
impl<T> MapLockoutStatusErrExt<T> for Result<T, LockoutStatus> {
    fn wrap_lockout_status_err(self) -> ServiceResult<T> {
        self.map_err(|e| ServiceError::AuthLockoutError(Box::new(e)))
    }
}

/// PERMANENT_DELAY indicates an infinite delay and the lockout is permanent.
/// It is the biggest duration value that trusty time::Instant could allow.
pub const PERMANENT_DELAY: Duration = Duration::from_nanos(i64::MAX as u64);

/// Default timeout window for fingerprint: 24 hours.
pub const DEFAULT_AUTH_TIMEOUT_WINDOW: Duration = Duration::from_secs(3600 * 24);

/// DelaySchedule indicates the delay must be waited for next attempt when the attempt count is met.
#[derive(Clone)]
pub struct DelaySchedule {
    attempt_count: u32,
    duration: Duration,
}

/// Default delay policy: permanent lockout after 5 attempts.
pub const DEFAULT_DELAY_POLICY: [DelaySchedule; 1] =
    [DelaySchedule { attempt_count: 5, duration: PERMANENT_DELAY }];

/// AuthRateLimiter manages the auth attempt counter and related lockout status.
pub struct AuthRateLimiter {
    attempt_counter: u32,
    next_attempt_locked_until: Instant,
    permanent_lockout_at: Instant,
    clock: &'static dyn Clock,
    delay_policy: Vec<DelaySchedule>,
}

impl AuthRateLimiter {
    /// Creates a new AuthRateLimiter with a given clock, a timeout window and an array of
    /// DelaySchedule.
    /// Past the timeout window, the rate limiter will permanently lock out any new auth attempt.
    /// The DelaySchedule array contains increasing delays for repeatedly auth attempts, including
    /// permanent delay that lock out new attempts as well.
    pub fn new(
        clock: &'static dyn Clock,
        timeout_window: Duration,
        delay_policy: Vec<DelaySchedule>,
    ) -> ServiceResult<Self> {
        Ok(Self {
            attempt_counter: 0,
            next_attempt_locked_until: Instant::MIN,
            permanent_lockout_at: clock.now()? + timeout_window,
            clock,
            delay_policy,
        })
    }
    // Returns the current lockout status, based on the current time.
    fn get_lockout_status(&self) -> Option<LockoutStatus> {
        let now = match self.clock.now() {
            Ok(instant) => instant,
            Err(_) => return Some(LockoutStatus::Unknown),
        };
        if (self.permanent_lockout_at <= now) || (self.next_attempt_locked_until == Instant::MAX) {
            return Some(LockoutStatus::Permanent);
        }
        if self.next_attempt_locked_until <= now {
            None
        } else {
            Some(LockoutStatus::Timed(self.next_attempt_locked_until - now))
        }
    }
    /// Returns the attempt counter if it is not locked out, otherwise an error
    /// indicating the lockout status. Should be used before authorizating a sensor session for
    /// authentication.
    pub fn increment_attempt_counter(&mut self) -> Result<u32, LockoutStatus> {
        let now = match self.clock.now() {
            Ok(instant) => instant,
            Err(_) => return Err(LockoutStatus::Unknown),
        };
        match self.get_lockout_status() {
            None => {
                self.attempt_counter += 1;
                // Find the schedule with highest attempt count that the current counter has
                // reached or exceeded.
                // And use the delay to compute when the lockout for the next attempt ends.
                let delay_schedule = self
                    .delay_policy
                    .iter()
                    .filter(|ds| ds.attempt_count <= self.attempt_counter)
                    .max_by_key(|ds| ds.attempt_count);
                self.next_attempt_locked_until = delay_schedule.map_or(Instant::MIN, |s| match s {
                    DelaySchedule { attempt_count: _, duration: PERMANENT_DELAY } => Instant::MAX,
                    DelaySchedule { attempt_count: _, ref duration } => now + *duration,
                });
                Ok(self.attempt_counter)
            }
            Some(status) => {
                // A permanent lockout is triggered by the new attempt => Effectively put the rate
                // limiter into the permanent lockout state by timing out immediately.
                if self.next_attempt_locked_until == Instant::MAX && now < self.permanent_lockout_at
                {
                    self.permanent_lockout_at = now;
                }
                Err(status)
            }
        }
    }
    /// Resets the attempt counter. Should be used after each successful authentication.
    /// Note that this method can only reset temporary lockout. Resetting a permanent lockout
    /// should come with a knowledge factor authentication where a new AuthRateLimiter with
    /// a renewed timeout window should be created instead.
    pub fn reset_attempt_counter(&mut self) {
        self.attempt_counter = 0;
        self.next_attempt_locked_until = Instant::MIN;
    }
}

#[cfg(test)]
mod test {
    use super::{AuthRateLimiter, DelaySchedule, LockoutStatus, PERMANENT_DELAY};
    use crate::fake::SimulatedClock;
    use std::time::Duration;

    #[test]
    fn test_auth_rate_limiter_new() {
        let clock = SimulatedClock::new();
        let time_window = Duration::from_secs(3600);
        let lockout_policy = [DelaySchedule { attempt_count: 1, duration: PERMANENT_DELAY }];
        let _ = AuthRateLimiter::new(clock, time_window, lockout_policy.to_vec()).unwrap();
    }

    #[test]
    fn test_rate_limiter_timeout() {
        let clock = SimulatedClock::new();
        let time_window = Duration::from_secs(3600);
        let lockout_policy = [DelaySchedule { attempt_count: 1, duration: PERMANENT_DELAY }];
        let mut rate_limiter =
            AuthRateLimiter::new(clock, time_window, lockout_policy.to_vec()).unwrap();
        clock.advance_time(time_window);
        // Past the timeout window, the rate limiter is permanently locked out.
        assert!(matches!(rate_limiter.increment_attempt_counter(), Err(LockoutStatus::Permanent)));
    }

    #[test]
    fn test_rate_limiter_timed_lockout() {
        let clock = SimulatedClock::new();
        let lockout_policy = [
            DelaySchedule { attempt_count: 1, duration: Duration::from_secs(30) },
            DelaySchedule { attempt_count: 2, duration: Duration::from_secs(60) },
            DelaySchedule { attempt_count: 3, duration: PERMANENT_DELAY },
        ];
        let time_window = Duration::from_secs(3600);
        const DURATION_30S: Duration = Duration::from_secs(30);
        const DURATION_60S: Duration = Duration::from_secs(60);
        let mut rate_limiter =
            AuthRateLimiter::new(clock, time_window, lockout_policy.to_vec()).unwrap();
        // 1st attempt is allowed immediately.
        assert!(matches!(rate_limiter.increment_attempt_counter(), Ok(1)));
        // 2nd attempt needs to wait for 30 seconds.
        assert!(matches!(
            rate_limiter.increment_attempt_counter(),
            Err(LockoutStatus::Timed(DURATION_30S)),
        ));
        // Wait 30 seconds and try again.
        clock.advance_time(DURATION_30S);
        assert!(matches!(rate_limiter.increment_attempt_counter(), Ok(2)));
        // 3rd attempt needs to wait for 60 seconds.
        assert!(matches!(
            rate_limiter.increment_attempt_counter(),
            Err(LockoutStatus::Timed(DURATION_60S)),
        ));
        // Wait 30 seconds and try again.
        clock.advance_time(DURATION_30S);
        assert!(matches!(
            rate_limiter.increment_attempt_counter(),
            Err(LockoutStatus::Timed(DURATION_30S)),
        ));
        // Wait another 30 seconds and try again.
        clock.advance_time(DURATION_30S);
        assert!(matches!(rate_limiter.increment_attempt_counter(), Ok(3)));
        // Now permanently locked out if increment the counter one more time.
        assert!(matches!(rate_limiter.increment_attempt_counter(), Err(LockoutStatus::Permanent)));
    }

    #[test]
    fn test_rate_limiter_reset_counter() {
        let clock = SimulatedClock::new();
        let n = 5;
        let lockout_policy = [DelaySchedule { attempt_count: n, duration: PERMANENT_DELAY }];
        let time_window = Duration::from_secs(3600);
        let mut rate_limiter =
            AuthRateLimiter::new(clock, time_window, lockout_policy.to_vec()).unwrap();
        // Initial n attempts are allowed immediately.
        for _ in 0..n {
            assert!(rate_limiter.increment_attempt_counter().is_ok());
        }
        // Reset the counter.
        rate_limiter.reset_attempt_counter();
        // New attempt is allowed again, and the counter starts over.
        assert!(matches!(rate_limiter.increment_attempt_counter(), Ok(1)));
    }

    #[test]
    fn test_rate_limiter_reset_does_nothing_after_permanent_lockout() {
        let clock = SimulatedClock::new();
        let n = 5;
        let lockout_policy = [DelaySchedule { attempt_count: n, duration: PERMANENT_DELAY }];
        let time_window = Duration::from_secs(3600);
        let mut rate_limiter =
            AuthRateLimiter::new(clock, time_window, lockout_policy.to_vec()).unwrap();
        // Initial n attempts are allowed immediately.
        for _ in 0..n {
            assert!(rate_limiter.increment_attempt_counter().is_ok());
        }
        // Now permanently locked out if increment the counter one more time.
        assert!(matches!(rate_limiter.increment_attempt_counter(), Err(LockoutStatus::Permanent)));
        // Reset the counter.
        rate_limiter.reset_attempt_counter();
        // New attempt is still locked out.
        assert!(matches!(rate_limiter.increment_attempt_counter(), Err(LockoutStatus::Permanent)));
    }
}
