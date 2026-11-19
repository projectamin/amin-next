//! Backend runtime state and the `p2c_ewma` balancer (proxy-plan §4.1/§5.4).
//!
//! A declared `<amin:backend>` is pure data.  What the listener needs on top of
//! that is *health* — a latency estimate and an in-flight count so several
//! candidates on one route can be balanced.  That state is not in the config
//! (the config is the immutable contract, §5.3); it lives here, one runtime
//! record per declared id, and is reused across requests.
//!
//! The policy is the same `p2c_ewma` the Perl front uses: two candidates are
//! sampled at random and the lower-scoring one wins.  This mirrors
//! `Amin::Proxy::Backend::Pool` so the two fronts make the same choice under
//! the same runtime state.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::Compiled;

/// Score of a backend with no measurement: an unmeasured peer must still be
/// tried, so it scores as one nominal second.
const DEFAULT_EWMA: f64 = 1.0;
/// EWMA weight — roughly the last five samples dominate.
const ALPHA: f64 = 0.2;
/// Consecutive connect failures before a backend is considered down.
const MAX_FAILS: u32 = 3;

#[derive(Default)]
struct Rt {
    ewma: Option<f64>,
    inflight: u32,
    fails: u32,
}

impl Rt {
    fn healthy(&self) -> bool {
        self.fails < MAX_FAILS
    }

    fn score(&self) -> f64 {
        self.ewma.unwrap_or(DEFAULT_EWMA) * f64::from(self.inflight + 1)
    }
}

/// Runtime state for every declared backend, plus the power-of-two chooser.
pub struct Pool {
    rt: Mutex<BTreeMap<String, Rt>>,
    rng: Mutex<u64>,
}

impl Pool {
    /// Build one runtime record per declared backend.
    #[must_use]
    pub fn new(cfg: &Compiled) -> Self {
        let rt = cfg.backends.keys().map(|id| (id.clone(), Rt::default())).collect();
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0x9E37_79B9_7F4A_7C15, |d| d.as_nanos() as u64);
        Self { rt: Mutex::new(rt), rng: Mutex::new(seed) }
    }

    /// Choose one backend id from the candidates a route emitted (proxy-plan
    /// §4.3): the router picks the set, the balancer chooses one.
    #[must_use]
    pub fn pick(&self, ids: &[&str]) -> Option<String> {
        let live: Vec<&str> = {
            let rt = self.rt.lock().expect("pool poisoned");
            ids.iter().copied().filter(|id| rt.contains_key(*id)).collect()
        };
        match live.len() {
            0 => None,
            1 => Some(live[0].to_string()),
            n => {
                let i = self.index(n);
                let mut j = self.index(n);
                if i == j {
                    j = (i + 1) % n;
                }
                let rt = self.rt.lock().expect("pool poisoned");
                let a = &rt[live[i]];
                let b = &rt[live[j]];
                let winner = match (a.healthy(), b.healthy()) {
                    (true, false) => i,
                    (false, true) => j,
                    _ if a.score() <= b.score() => i,
                    _ => j,
                };
                Some(live[winner].to_string())
            }
        }
    }

    /// Mark a backend in flight.
    pub fn begin(&self, id: &str) {
        if let Some(r) = self.rt.lock().expect("pool poisoned").get_mut(id) {
            r.inflight += 1;
        }
    }

    /// Mark a backend's request done, folding the observed latency in.
    pub fn done(&self, id: &str, latency: Option<f64>) {
        if let Some(r) = self.rt.lock().expect("pool poisoned").get_mut(id) {
            r.inflight = r.inflight.saturating_sub(1);
            r.fails = 0;
            if let Some(l) = latency {
                r.ewma = Some(match r.ewma {
                    Some(e) => ALPHA * l + (1.0 - ALPHA) * e,
                    None => l,
                });
            }
        }
    }

    /// Mark a connect failure.
    pub fn fail(&self, id: &str) {
        if let Some(r) = self.rt.lock().expect("pool poisoned").get_mut(id) {
            r.inflight = r.inflight.saturating_sub(1);
            r.fails += 1;
        }
    }

    /// A value in `0..n` from the pool's xorshift stream.
    fn index(&self, n: usize) -> usize {
        let mut s = self.rng.lock().expect("rng poisoned");
        *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z >> 11) as usize % n
    }
}
