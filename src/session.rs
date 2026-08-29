//! The session's connectivity at a glance: one coarse cell per slice of time,
//! covering the whole run from the first tick to now.
//!
//! The rest of the dashboard answers "what is happening"; over a long session —
//! a flight, an evening of congestion — the question becomes "what has been
//! happening", and by then the latency graph's ring buffer has long since
//! rolled over. This keeps the shape of the whole session in a single row by
//! trading resolution for span: cells fold in pairs and the time each one
//! covers doubles, so the strip never scrolls and never runs out.
//!
//! Folding always takes the *worst* state in the cell, never an average. A
//! ninety-second outage three hours ago still shows as a red cell at hour six
//! instead of dissolving into the green either side of it.

use std::collections::VecDeque;

/// How one slice of the session read. Ordered worst-last: folding is `max`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum SessionState {
    /// Nothing measured yet, or not enough data to judge.
    #[default]
    Unknown,
    Healthy,
    /// Working badly but working — including "degraded but usable", the state
    /// a plane or hotel network spends its whole life in.
    Degraded,
    /// The connection, not one destination, was failing.
    Down,
}

/// Cells kept before folding. Comfortably wider than any terminal, so the
/// render downsamples from a finer record than it can draw rather than the
/// other way round.
const CELLS: usize = 512;

/// One cell of the record: how it read, when it began, and what was wrong.
#[derive(Clone, Copy, Debug)]
struct Cell {
    state: SessionState,
    /// Unix seconds at which this cell's span opened.
    from: i64,
    /// The cause behind the worst tick in the cell — the bar's answer to
    /// "what was that?" without having to hold the whole finding.
    cause: Option<crate::verdict::Cause>,
}

/// A drawn column: one cell of the bar, and the span of the session it covers.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Slice {
    pub state: SessionState,
    pub cause: Option<crate::verdict::Cause>,
    /// Unix seconds, inclusive.
    pub from: i64,
    /// Unix seconds: where the next column starts, or now for the last one.
    pub to: i64,
}

#[derive(Clone)]
pub struct SessionTrack {
    /// Oldest first; the last cell is the one currently filling.
    cells: VecDeque<Cell>,
    /// Ticks a cell covers. Doubles each time the ring fills.
    ticks_per_cell: u32,
    /// Ticks already folded into the cell currently filling.
    filled: u32,
}

impl Default for SessionTrack {
    fn default() -> Self {
        Self {
            cells: VecDeque::with_capacity(CELLS),
            ticks_per_cell: 1,
            filled: 0,
        }
    }
}

impl SessionTrack {
    /// Fold one tick's state in, with the cause behind it when there was one.
    pub fn record(&mut self, state: SessionState, cause: Option<crate::verdict::Cause>) {
        let at = chrono::Utc::now().timestamp();
        if self.filled == 0 {
            self.cells.push_back(Cell {
                state,
                from: at,
                cause,
            });
        } else if let Some(last) = self.cells.back_mut() {
            // The worst tick in the cell owns it, and brings its cause: a
            // minute that was down for one second reads as down, and says
            // what was down.
            if state > last.state {
                last.state = state;
                last.cause = cause;
            }
        }
        self.filled += 1;
        if self.filled >= self.ticks_per_cell {
            self.filled = 0;
        }
        if self.cells.len() > CELLS {
            self.compress();
        }
    }

    /// Halve the ring by folding neighbouring pairs, doubling the time each
    /// cell covers. The session keeps its full span; it just gets coarser.
    fn compress(&mut self) {
        let odd = self.cells.len() % 2 == 1;
        // Ticks in the cell currently filling — a full one when `filled` has
        // just wrapped to zero.
        let tail_ticks = if self.filled == 0 {
            self.ticks_per_cell
        } else {
            self.filled
        };

        let mut folded = VecDeque::with_capacity(CELLS);
        let mut it = self.cells.iter().copied();
        while let Some(a) = it.next() {
            folded.push_back(match it.next() {
                // The worse half wins the merged cell, but the span still
                // starts where the pair started.
                Some(b) if b.state > a.state => Cell { from: a.from, ..b },
                Some(_) | None => a,
            });
        }
        self.cells = folded;
        self.ticks_per_cell = self.ticks_per_cell.saturating_mul(2);

        // Keep the fill boundary honest: an odd tail leaves the new last cell
        // holding only the old one's ticks, an even one a whole old cell plus
        // that tail.
        let mut filled = if odd {
            tail_ticks
        } else {
            self.ticks_per_cell / 2 + tail_ticks
        };
        if filled >= self.ticks_per_cell {
            filled = 0;
        }
        self.filled = filled;
    }

    /// The bar at a given width, oldest column first: the worst state in each
    /// column's stretch of the session, what caused it, and the span of time
    /// it covers.
    ///
    /// The columns divide the record evenly rather than in fixed-size groups,
    /// so the bar fills the row it is given and both ends stay anchored: the
    /// session's first tick at the left edge, now at the right. The spans are
    /// what make the bar navigable — every column can say which minutes it
    /// stands for.
    pub fn slices(&self, width: usize) -> Vec<Slice> {
        let n = self.cells.len();
        if width == 0 || n == 0 {
            return Vec::new();
        }
        let src: Vec<Cell> = self.cells.iter().copied().collect();
        let bounds: Vec<(usize, usize)> = if n <= width {
            (0..n).map(|i| (i, i + 1)).collect()
        } else {
            (0..width)
                .map(|i| {
                    let from = i * n / width;
                    (from, ((i + 1) * n / width).max(from + 1))
                })
                .collect()
        };
        let now = chrono::Utc::now().timestamp();
        bounds
            .iter()
            .enumerate()
            .map(|(i, (a, b))| {
                let group = &src[*a..*b];
                let worst = group
                    .iter()
                    .max_by_key(|c| c.state)
                    .copied()
                    .unwrap_or(group[0]);
                Slice {
                    state: worst.state,
                    cause: worst.cause,
                    from: group[0].from,
                    // A column ends where the next one starts; the newest ends
                    // at now, which is what it is still filling towards.
                    to: bounds.get(i + 1).map_or(now, |(next, _)| src[*next].from),
                }
            })
            .collect()
    }

    /// Ticks recorded in total — cells times what each one covers, plus the
    /// one being filled. The strip carries no clock of its own (the header
    /// counts the session), so this exists for the tests that pin the folding
    /// arithmetic.
    #[cfg(test)]
    fn ticks(&self) -> u64 {
        let full = self.cells.len().saturating_sub(1) as u64 * self.ticks_per_cell as u64;
        let tail = if self.filled == 0 {
            self.ticks_per_cell as u64
        } else {
            self.filled as u64
        };
        if self.cells.is_empty() {
            0
        } else {
            full + tail
        }
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The drawn states at a width — what the bar renders, without the
    /// spans.
    fn drawn(t: &SessionTrack, width: usize) -> Vec<SessionState> {
        t.slices(width).into_iter().map(|s| s.state).collect()
    }

    fn track(states: &[SessionState]) -> SessionTrack {
        let mut t = SessionTrack::default();
        for s in states {
            t.record(*s, None);
        }
        t
    }

    #[test]
    fn a_short_session_is_one_cell_per_tick() {
        use SessionState::*;
        let t = track(&[Healthy, Healthy, Down, Healthy]);
        assert_eq!(drawn(&t, 80), vec![Healthy, Healthy, Down, Healthy]);
        assert_eq!(t.ticks(), 4);
    }

    /// The whole point: a long session keeps its full span. Cells fold in
    /// pairs and the strip stops growing, but the oldest tick is still in it.
    #[test]
    fn a_long_session_folds_instead_of_scrolling() {
        let mut t = SessionTrack::default();
        // One bad second at the very start, then hours of calm.
        t.record(SessionState::Down, None);
        for _ in 0..20_000 {
            t.record(SessionState::Healthy, None);
        }
        assert!(t.cells.len() <= CELLS, "the ring stops growing");
        assert_eq!(t.ticks(), 20_001, "every tick is still accounted for");
        // Folding takes the worst, so an outage never averages away.
        let drawn = drawn(&t, 100);
        assert_eq!(drawn.len(), 100);
        assert_eq!(
            drawn[0],
            SessionState::Down,
            "the outage at the start survives to the far left"
        );
        assert!(
            drawn[1..].iter().all(|c| *c == SessionState::Healthy),
            "and stays where it happened"
        );
    }

    /// Ticks per cell stay in step with the folding: after N compressions a
    /// cell covers 2^N ticks, and no tick has been lost or double-counted.
    #[test]
    fn folding_keeps_the_clock_honest() {
        let mut t = SessionTrack::default();
        for _ in 0..(CELLS * 4 + 7) {
            t.record(SessionState::Healthy, None);
        }
        assert_eq!(t.ticks_per_cell, 8);
        assert_eq!(t.ticks(), (CELLS * 4 + 7) as u64);
    }

    /// "now" belongs at the right edge: downsampling must not shift the
    /// newest cell inwards to make the groups come out even.
    #[test]
    fn the_newest_cell_stays_flush_right() {
        let mut t = SessionTrack::default();
        for _ in 0..99 {
            t.record(SessionState::Healthy, None);
        }
        t.record(SessionState::Down, None);
        let drawn = drawn(&t, 7);
        assert_eq!(*drawn.last().unwrap(), SessionState::Down);
        assert!(drawn.len() <= 7);
    }

    #[test]
    fn an_unmeasured_start_reads_as_unknown_not_healthy() {
        use SessionState::*;
        let t = track(&[Unknown, Unknown, Healthy]);
        assert_eq!(drawn(&t, 3), vec![Unknown, Unknown, Healthy]);
    }
}
