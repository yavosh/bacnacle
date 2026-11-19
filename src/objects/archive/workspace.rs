//! Admission for concurrent XZ and 7z decoder workspaces on the reference host.

use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Condvar, Mutex, Weak},
    time::Duration,
};

pub(super) const BUDGET: u64 = 512 << 20;
static POOL: (Mutex<State>, Condvar) = (
    Mutex::new(State {
        used: 0,
        waiting: VecDeque::new(),
    }),
    Condvar::new(),
);

struct State {
    used: u64,
    waiting: VecDeque<Weak<()>>,
}

pub(super) struct Lease(u64);

impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = POOL.0.lock().unwrap_or_else(|error| error.into_inner());
        state.used -= self.0;
        POOL.1.notify_all();
    }
}

// Queue larger requests fairly. An existing supported decode above the budget
// runs alone. Callers must drop the lease before recursive object traversal.
pub(super) fn acquire(bytes: u64, mut check: impl FnMut() -> io::Result<()>) -> io::Result<Lease> {
    check()?;
    let weight = bytes.clamp(1, BUDGET);
    let mut state = POOL.0.lock().unwrap_or_else(|error| error.into_inner());
    if state.waiting.is_empty() && state.used + weight <= BUDGET {
        state.used += weight;
        return Ok(Lease(weight));
    }
    let ticket = Arc::new(());
    let position = Arc::downgrade(&ticket);
    state.waiting.push_back(position.clone());
    loop {
        // A user-supplied cancellation callback can also unwind. Its weak
        // queue entry must not block subsequent scanner requests.
        while state
            .waiting
            .front()
            .is_some_and(|head| head.strong_count() == 0)
        {
            state.waiting.pop_front();
        }
        if state.used + weight <= BUDGET
            && state
                .waiting
                .front()
                .is_some_and(|head| Weak::ptr_eq(head, &position))
        {
            state.waiting.pop_front();
            state.used += weight;
            POOL.1.notify_all();
            return Ok(Lease(weight));
        }
        let (guard, _) = POOL
            .1
            .wait_timeout(state, Duration::from_millis(10))
            .unwrap_or_else(|error| error.into_inner());
        drop(guard);
        let checked = check();
        state = POOL.0.lock().unwrap_or_else(|error| error.into_inner());
        if let Err(error) = checked {
            state
                .waiting
                .retain(|entry| !Weak::ptr_eq(entry, &position));
            POOL.1.notify_all();
            return Err(error);
        }
    }
}

// The LZ window starts at 64 KiB and grows geometrically. Include lookahead,
// range and literal decoder buffers, independently of the declared dictionary.
pub(super) fn history(output: u64) -> u64 {
    output.saturating_add(8192).saturating_mul(2).max(64 << 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancelled_waiter_releases_its_place() -> io::Result<()> {
        let first = acquire(BUDGET, || Ok(()))?;
        let mut checks = 0;
        let cancelled = acquire(1, || {
            checks += 1;
            if checks > 1 {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Ok(())
            }
        });
        assert!(matches!(cancelled, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        drop(first);
        let _next = acquire(BUDGET + 1, || Ok(()))?;
        Ok(())
    }
}
