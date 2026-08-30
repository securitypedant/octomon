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

/// The finding behind a cell's worst tick — what made it yellow or red.
///
/// Carried by the bar itself rather than reconstructed from the timeline
/// later: a stretch of colour usually contains no timeline entries at all
/// (the finding raised before it and cleared after it), so "what was that?"
/// is a question only the bar can answer, and it can only answer it if it
/// kept the answer at the time.
#[derive(Clone, Debug)]
pub struct Mark {
    /// When the episode raised — the point the timeline should open at.
    pub since: i64,
    /// The finding's own one-liner, as the footer and the timeline word it.
    pub summary: std::sync::Arc<str>,
}

/// One cell of the record: how it read, when it began, and what was wrong.
#[derive(Clone, Debug)]
struct Cell {
    state: SessionState,
    /// Unix seconds at which this cell's span opened.
    from: i64,
    /// The finding behind the worst tick in it, when there was one.
    mark: Option<Mark>,
}

/// How much of the session the bar is showing.
///
/// Not a ladder of scales, and not a fixed "recent" window: a lens held over
/// the moment the cursor is on. Walk to the interesting patch, zoom, and the
/// row becomes the hour around it — which makes "the last hour" simply what
/// you get by zooming at the right-hand end, without a second mode to explain.
///
/// Resolution is still whatever the ring holds: on a nine-hour session each
/// cell already covers about a minute, and zooming cannot invent the seconds
/// back. It buys width for the minutes that are there, not new detail.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum BarScope {
    #[default]
    Session,
    /// Unix seconds, inclusive of `from`, exclusive of `to`.
    Window { from: i64, to: i64 },
}

/// How far either side of the cursor a zoom reaches.
pub const ZOOM_HALF_SPAN: i64 = 1800;

/// A drawn column: one cell of the bar, and the span of the session it covers.
#[derive(Clone, Debug)]
pub struct Slice {
    pub state: SessionState,
    /// The finding behind this column, when it was not healthy.
    pub mark: Option<Mark>,
    /// Unix seconds, inclusive.
    pub from: i64,
    /// Unix seconds: where the next column starts, or now for the last one.
    pub to: i64,
}

/// How long the analysis may be unable to judge before the bar says so.
///
/// Sized against what a network change costs: switching a VPN on resets every
/// probe window, and the verdict reads "measuring…" until a target has
/// gathered `MIN_SAMPLES` outcomes again — through an 8 s settle grace, so
/// ten to fifteen seconds. Painting that reads as damage, and worse, as the
/// bar having reset itself: it is octomon re-establishing its own footing,
/// not the connection failing. Past this, a gap is real and gets drawn.
const UNMEASURED_GRACE_TICKS: u32 = 20;

#[derive(Clone)]
pub struct SessionTrack {
    /// Oldest first; the last cell is the one currently filling.
    cells: VecDeque<Cell>,
    /// Ticks a cell covers. Doubles each time the ring fills.
    ticks_per_cell: u32,
    /// Ticks already folded into the cell currently filling.
    filled: u32,
    /// Consecutive ticks the analysis has had no opinion on.
    unmeasured_run: u32,
}

impl Default for SessionTrack {
    fn default() -> Self {
        Self {
            cells: VecDeque::with_capacity(CELLS),
            ticks_per_cell: 1,
            filled: 0,
            unmeasured_run: 0,
        }
    }
}

impl SessionTrack {
    /// Fold one tick's state in, with the finding behind it when there was one.
    pub fn record(&mut self, state: SessionState, mark: Option<Mark>) {
        // The seconds before the analysis has anything to say are not a state
        // the bar should open with: they left a grey stub pinned to the left
        // edge for the rest of the session, which reads as a defect rather
        // than as "measuring". The bar starts when the measuring does.
        if state == SessionState::Unknown && self.cells.is_empty() {
            return;
        }
        // Nor does a short spell of not-knowing change what the bar says. A
        // VPN coming up or the network moving resets every probe window, and
        // the seconds spent refilling them are octomon's, not the
        // connection's — so the bar holds its state through them and only
        // draws a gap once one has lasted (see UNMEASURED_GRACE_TICKS).
        let (state, mark) = if state == SessionState::Unknown {
            self.unmeasured_run = self.unmeasured_run.saturating_add(1);
            match self.cells.back() {
                Some(last) if self.unmeasured_run <= UNMEASURED_GRACE_TICKS => {
                    (last.state, last.mark.clone())
                }
                _ => (SessionState::Unknown, None),
            }
        } else {
            self.unmeasured_run = 0;
            (state, mark)
        };
        let at = chrono::Utc::now().timestamp();
        if self.filled == 0 {
            self.cells.push_back(Cell {
                state,
                from: at,
                mark,
            });
        } else if let Some(last) = self.cells.back_mut() {
            // The worst tick in the cell owns it, and brings its finding: a
            // minute that was down for one second reads as down, and says
            // what was down.
            if state > last.state {
                last.state = state;
                last.mark = mark;
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
        let mut it = self.cells.iter().cloned();
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
    /// The columns divide the record evenly, and there are always exactly
    /// `width` of them: the bar spans the row it is given from the very first
    /// second of the session, and both ends stay anchored — session start at
    /// the left edge, now at the right — at every age.
    ///
    /// A session shorter than the row is *stretched* across it rather than
    /// drawn short and padded. That keeps one rule true the whole way through
    /// ("this row is the session, left to right") instead of having the bar
    /// grow in from the right for the first two minutes and then start
    /// compressing. Several columns simply share a cell early on, and each of
    /// them reports that cell's real span, so nothing is invented.
    pub fn slices(&self, width: usize, scope: BarScope) -> Vec<Slice> {
        let n = self.cells.len();
        if width == 0 || n == 0 {
            return Vec::new();
        }
        let src: Vec<Cell> = self.cells.iter().cloned().collect();
        let now = chrono::Utc::now().timestamp();
        // A cell runs until the next one opens; the newest runs up to now.
        let end_of = |i: usize| src.get(i + 1).map_or(now, |c: &Cell| c.from);
        // Zoomed, the row draws only the cells overlapping the window — at
        // least one, so a window over a quiet stretch still shows what was
        // there rather than going blank.
        let (lo, hi) = match scope {
            BarScope::Session => (0, n),
            BarScope::Window { from, to } => {
                let lo = (0..n).find(|i| end_of(*i) > from).unwrap_or(n - 1);
                let hi = (lo..n).find(|i| src[*i].from >= to).unwrap_or(n);
                (lo, hi.max(lo + 1))
            }
        };
        let n = hi - lo;
        (0..width)
            .map(|i| {
                let a = lo + i * n / width;
                let b = (lo + ((i + 1) * n / width)).max(a + 1).min(hi);
                let group = &src[a..b];
                let worst = group.iter().max_by_key(|c| c.state).unwrap_or(&group[0]);
                Slice {
                    state: worst.state,
                    mark: worst.mark.clone(),
                    from: group[0].from,
                    // The span is the *cells'*, not the column's: several
                    // columns sharing a cell all report the seconds that cell
                    // actually covers, and the newest runs up to now.
                    to: src.get(b).map_or(now, |next| next.from),
                }
            })
            .collect()
    }

    /// A track with cells at chosen times: `(state, seconds after `start`)`.
    ///
    /// Tests need a session that spans hours, and a test cannot wait for one
    /// — every `record` inside a test lands in the same wall-clock second, so
    /// the spans (and everything drawn from them: ticks, the readout, the
    /// zoom) would all collapse to zero.
    #[cfg(test)]
    pub fn seeded(start: i64, cells: &[(SessionState, i64)]) -> Self {
        let mut t = Self::default();
        for (state, offset) in cells {
            t.cells.push_back(Cell {
                state: *state,
                from: start + offset,
                mark: None,
            });
        }
        t
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
        t.slices(width, BarScope::Session)
            .into_iter()
            .map(|s| s.state)
            .collect()
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
        assert_eq!(drawn(&t, 4), vec![Healthy, Healthy, Down, Healthy]);
        assert_eq!(t.ticks(), 4);

        // Asked for a wider row, the same four seconds stretch across all of
        // it — the bar is always the session, edge to edge — and the shape
        // survives the stretch.
        let wide = drawn(&t, 80);
        assert_eq!(wide.len(), 80);
        assert_eq!(wide[0], Healthy);
        assert_eq!(*wide.last().unwrap(), Healthy);
        assert_eq!(wide.iter().filter(|c| **c == Down).count(), 20, "a quarter");
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

    /// The VPN case, reported from a real session: switching NordVPN on reset
    /// every probe window, the verdict went back to "measuring…" while they
    /// refilled, and the bar painted that as a run of dark cells — which read
    /// first as the bar having reset itself, then as damage. Nothing about
    /// the connection had changed; octomon had lost its own footing for ten
    /// seconds.
    #[test]
    fn a_network_change_does_not_punch_a_hole_in_the_bar() {
        use SessionState::*;
        let mut states = vec![Healthy; 60];
        // The switch: ~12 s of no opinion, then healthy on the new path.
        states.extend(std::iter::repeat_n(Unknown, 12));
        states.extend(std::iter::repeat_n(Healthy, 60));
        let t = track(&states);

        let drawn = drawn(&t, states.len());
        assert!(
            !drawn.contains(&Unknown),
            "the re-settling shows as nothing at all: {drawn:?}"
        );
        assert_eq!(t.ticks(), states.len() as u64, "the time is still counted");
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
    /// The seconds before the analysis can say anything are not the bar's
    /// opening state: recorded, they left a grey stub pinned to the left edge
    /// for the rest of the session, which reads as a rendering fault rather
    /// than as "measuring". Once the bar has started, an unmeasured stretch
    /// is real and stays.
    fn the_bar_starts_when_the_measuring_does() {
        use SessionState::*;
        let t = track(&[Unknown, Unknown, Healthy]);
        assert_eq!(drawn(&t, 1), vec![Healthy], "the stub never lands");
        assert_eq!(t.ticks(), 1);

        // A short spell of not-knowing is octomon re-establishing itself
        // after a network change, not the connection changing: the bar holds
        // what it had rather than punching a hole in itself.
        let blip = track(&[Healthy, Unknown, Healthy]);
        assert_eq!(drawn(&blip, 3), vec![Healthy, Healthy, Healthy]);

        // A sustained one is real, and gets drawn.
        let mut long = vec![(Healthy)];
        long.extend(std::iter::repeat_n(
            Unknown,
            UNMEASURED_GRACE_TICKS as usize + 5,
        ));
        long.push(Healthy);
        let t = track(&long);
        let states = drawn(&t, long.len());
        assert!(
            states.contains(&Unknown),
            "a gap past the grace is a fact about the session: {states:?}"
        );
        // …and only past it: the first seconds still read as before.
        assert_eq!(states[1], Healthy, "the grace holds the previous state");
        assert_eq!(*states.last().unwrap(), Healthy, "and it recovers");
    }
}
