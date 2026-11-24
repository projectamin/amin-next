//! Witness-quorum policy for offline acceptance.
//!
//! A receipt proves *the payer's own key* committed to a payment.  It does not
//! prove the payer showed the same history to everyone else, so a payer that
//! forks its log can double-spend until the fork is observed.  Witnesses close
//! that window: a witness cosigns an origin's checkpoint only if it extends the
//! last one that witness saw (see `Ledger::witness_review`), so two conflicting
//! checkpoints can never both gather a quorum of honest cosignatures.
//!
//! The price of waiting for witnesses is latency, so the quorum scales with the
//! value at risk: small payments are accepted on the payer's signature alone,
//! larger ones need more witnesses.  A missing or unreadable amount is treated
//! as the highest tier (fail closed).

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QuorumPolicy {
    /// Witnesses always required (usually 0 for micro-payments).
    pub base: usize,
    /// `(amount ≥, witnesses)` — the highest matching tier wins.
    pub tiers: Vec<(u64, usize)>,
}

impl QuorumPolicy {
    /// The same quorum for every receipt.
    pub fn flat(q: usize) -> Self {
        Self { base: q, tiers: Vec::new() }
    }

    /// Parse `"100:2"` style tier specs.
    pub fn with_tiers(base: usize, specs: &[String]) -> Result<Self, String> {
        let mut tiers = Vec::new();
        for s in specs {
            let (a, q) = s.split_once(':').ok_or_else(|| format!("bad tier {s:?}, want AMOUNT:QUORUM"))?;
            tiers.push((a.parse().map_err(|_| format!("bad amount in {s:?}"))?, q.parse().map_err(|_| format!("bad quorum in {s:?}"))?));
        }
        tiers.sort();
        Ok(Self { base, tiers })
    }

    /// Witnesses required for a payment of `amount` (`None` = unknown ⇒ strictest).
    pub fn required(&self, amount: Option<u64>) -> usize {
        match amount {
            None => self.tiers.iter().map(|t| t.1).fold(self.base, usize::max),
            Some(a) => self.tiers.iter().filter(|t| a >= t.0).map(|t| t.1).fold(self.base, usize::max),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_scale_with_value_and_fail_closed() {
        let p = QuorumPolicy::with_tiers(0, &["100:1".into(), "1000:2".into()]).unwrap();
        assert_eq!(p.required(Some(5)), 0);
        assert_eq!(p.required(Some(100)), 1);
        assert_eq!(p.required(Some(999)), 1);
        assert_eq!(p.required(Some(1000)), 2);
        assert_eq!(p.required(None), 2, "unknown amount takes the strictest tier");
        assert_eq!(QuorumPolicy::flat(3).required(Some(1)), 3);
        assert!(QuorumPolicy::with_tiers(0, &["x".into()]).is_err());
    }
}
