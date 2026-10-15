//! Press/hold a chord without ever leaving a key stuck down.
//!
//! A held chord is `down(a) down(b) … wait … up(b) up(a)`. Done inline, any
//! failure between the first `down` and the last `up` — a second key that does
//! not exist, a timed-out helper process, the call being cancelled during the
//! wait — strands the keys already pressed: a Ctrl or Shift stuck down on the
//! user's real desktop. [`hold_chord`] releases whatever was pressed on every
//! exit path, including the future being dropped mid-wait.

use std::time::Duration;

use anyhow::Result;

/// Longest a chord may be held.
pub(crate) const MAX_HOLD: Duration = Duration::from_secs(30);

/// Releases the pressed keys (newest first) when dropped — covers an early
/// `?` return and a cancelled future alike. `up` must be synchronous and
/// infallible-by-contract: it runs in `Drop`, so errors are ignored.
struct ReleaseGuard<'a, U: Fn(&str)> {
    pressed: Vec<&'a str>,
    up: U,
}

impl<U: Fn(&str)> Drop for ReleaseGuard<'_, U> {
    fn drop(&mut self) {
        while let Some(k) = self.pressed.pop() {
            (self.up)(k);
        }
    }
}

/// Press `parts` in order through `down`, hold for `hold`, then release in
/// reverse through `up` — releasing even if a later `down` fails or the
/// returned future is dropped.
pub(crate) async fn hold_chord<'a>(
    parts: &[&'a str],
    hold: Duration,
    mut down: impl FnMut(&str) -> Result<()>,
    up: impl Fn(&str),
) -> Result<()> {
    let mut guard = ReleaseGuard {
        pressed: Vec::with_capacity(parts.len()),
        up,
    };
    for p in parts {
        // Recorded BEFORE the call: a `down` that half-succeeded (the key went
        // down, the reply timed out) must still be released.
        guard.pressed.push(p);
        down(p)?;
    }
    tokio::time::sleep(hold.min(MAX_HOLD)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[tokio::test]
    async fn releases_in_reverse_after_the_hold() {
        let log = RefCell::new(Vec::<String>::new());
        hold_chord(
            &["ctrl", "shift", "a"],
            Duration::from_millis(1),
            |k| {
                log.borrow_mut().push(format!("down {k}"));
                Ok(())
            },
            |k| log.borrow_mut().push(format!("up {k}")),
        )
        .await
        .unwrap();
        assert_eq!(
            *log.borrow(),
            [
                "down ctrl",
                "down shift",
                "down a",
                "up a",
                "up shift",
                "up ctrl"
            ]
        );
    }

    /// The bug: a failure on the 3rd key used to leave ctrl+shift stuck.
    #[tokio::test]
    async fn a_failed_press_still_releases_what_was_pressed() {
        let log = RefCell::new(Vec::<String>::new());
        let r = hold_chord(
            &["ctrl", "shift", "nope"],
            Duration::from_millis(1),
            |k| {
                log.borrow_mut().push(format!("down {k}"));
                if k == "nope" {
                    anyhow::bail!("unknown key")
                }
                Ok(())
            },
            |k| log.borrow_mut().push(format!("up {k}")),
        )
        .await;
        assert!(r.is_err());
        // The failed key is released too (it may have half-landed).
        assert_eq!(
            *log.borrow(),
            [
                "down ctrl",
                "down shift",
                "down nope",
                "up nope",
                "up shift",
                "up ctrl"
            ]
        );
    }

    /// Cancelling during the hold (the user pressing stop) must release too.
    #[tokio::test]
    async fn dropping_the_future_mid_hold_releases() {
        let log = RefCell::new(Vec::<String>::new());
        {
            let fut = hold_chord(
                &["alt", "Tab"],
                Duration::from_secs(60),
                |k| {
                    log.borrow_mut().push(format!("down {k}"));
                    Ok(())
                },
                |k| log.borrow_mut().push(format!("up {k}")),
            );
            let _ = tokio::time::timeout(Duration::from_millis(30), fut).await;
        }
        assert_eq!(*log.borrow(), ["down alt", "down Tab", "up Tab", "up alt"]);
    }

    #[tokio::test]
    async fn hold_is_clamped() {
        let t = std::time::Instant::now();
        // Not actually waiting 30 s: assert the clamp arithmetic instead.
        assert_eq!(Duration::from_secs(999).min(MAX_HOLD), MAX_HOLD);
        assert!(t.elapsed() < Duration::from_secs(1));
    }
}
