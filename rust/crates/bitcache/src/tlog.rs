//! Tamper-evident append-only log — the Amin ledger core.
//!
//! A Merkle tree over BLAKE3 with the RFC 6962 / RFC 9162 shape
//! (`leaf = H(0x00‖entry)`, `node = H(0x01‖left‖right)`), so inclusion and
//! consistency proofs are the standard ones and a third party can audit a log
//! knowing nothing about Amin.
//!
//! Cost model (this is the "very lightweight" part):
//! * append is amortised O(1): one leaf hash plus, on average, one node hash;
//! * the head is a checkpoint, and only the *checkpoint* is signed — one
//!   signature per batch, never per entry;
//! * proofs are O(log n) hashes; verification needs no stored state.
//!
//! Quantum safety: nothing here is a public-key primitive.  Security rests on
//! BLAKE3-256 collision / second-preimage resistance (≥128 classical bits;
//! the generic quantum collision attack needs hardware this size of memory
//! makes impractical, and second-preimage via Grover is still 2^128 work).
//! All signatures over the head are post-quantum (see [`crate::checkpoint`]).

pub type Hash = [u8; 32];

/// `H(0x00 ‖ data)`.
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00]);
    h.update(data);
    *h.finalize().as_bytes()
}

/// `H(0x01 ‖ l ‖ r)`.
pub fn node_hash(l: &Hash, r: &Hash) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[0x01]);
    h.update(l);
    h.update(r);
    *h.finalize().as_bytes()
}

/// Root of the empty tree: `H("")` (RFC 9162 §2.1.1).
pub fn empty_root() -> Hash {
    *blake3::hash(&[]).as_bytes()
}

/// Largest power of two strictly less than `n` (`n >= 2`).
fn split(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1u64 << (63 - (n - 1).leading_zeros())
}

#[derive(Default, Debug, Clone)]
struct Level {
    /// Index of the first stored node at this level.
    off: u64,
    v: Vec<Hash>,
}

impl Level {
    fn get(&self, j: u64) -> Option<Hash> {
        let k = j.checked_sub(self.off)?;
        self.v.get(usize::try_from(k).ok()?).copied()
    }
    fn end(&self) -> u64 {
        self.off + self.v.len() as u64
    }
}

/// Append-only tree: `levels[h]` holds complete subtrees of `2^h` leaves.
///
/// A tree may be *pruned*: seeded from a [`frontier`](Tree::frontier) instead of
/// the full history.  It then stores only the frontier plus everything appended
/// since, i.e. memory is O(log n + entries since join).  Proofs that only touch
/// retained nodes — in particular every consistency proof from the join point to
/// a later head, and inclusion proofs for entries since the join — work as
/// normal; asking for a pruned node answers `None`.
#[derive(Default, Debug, Clone)]
pub struct Tree {
    levels: Vec<Level>,
}

/// The root a frontier commits to (`None` if its length is not `popcount(size)`).
pub fn fold_frontier(size: u64, frontier: &[Hash]) -> Option<Hash> {
    if frontier.len() != size.count_ones() as usize {
        return None;
    }
    let mut it = frontier.iter().rev();
    let Some(last) = it.next() else { return Some(empty_root()) };
    Some(it.fold(*last, |r, f| node_hash(f, &r)))
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resume from a frontier (highest subtree first).  The caller must have
    /// checked `fold_frontier(size, frontier)` against a trusted root.
    pub fn from_frontier(size: u64, frontier: &[Hash]) -> Option<Self> {
        if frontier.len() != size.count_ones() as usize {
            return None;
        }
        let nlevels = (64 - size.leading_zeros()) as usize;
        let mut levels = Vec::with_capacity(nlevels);
        let mut it = frontier.iter();
        for h in (0..nlevels).rev() {
            let count = size >> h;
            if (size >> h) & 1 == 1 {
                levels.push(Level { off: count - 1, v: vec![*it.next()?] });
            } else {
                levels.push(Level { off: count, v: Vec::new() });
            }
        }
        levels.reverse();
        Some(Self { levels })
    }

    /// Frontier at the current size (highest subtree first): O(log n) hashes.
    pub fn frontier(&self) -> Vec<Hash> {
        self.frontier_at(self.size()).expect("own frontier is always retained")
    }

    /// Frontier at an earlier `size`, if those nodes are still retained.
    pub fn frontier_at(&self, size: u64) -> Option<Vec<Hash>> {
        if size > self.size() {
            return None;
        }
        (0..64usize).rev().filter(|h| (size >> h) & 1 == 1).map(|h| self.levels.get(h)?.get((size >> h) - 1)).collect()
    }

    /// First leaf index whose hash is still stored.
    pub fn retained_from(&self) -> u64 {
        self.levels.first().map_or(0, |l| l.off)
    }

    pub fn size(&self) -> u64 {
        self.levels.first().map_or(0, Level::end)
    }

    /// Append an already-hashed leaf; returns its index.
    pub fn append_leaf_hash(&mut self, lh: Hash) -> u64 {
        let idx = self.size();
        if self.levels.is_empty() {
            self.levels.push(Level::default());
        }
        self.levels[0].v.push(lh);
        let mut h = 0;
        while self.levels[h].end() % 2 == 0 {
            let n = self.levels[h].end();
            let l = self.levels[h].get(n - 2).expect("left sibling retained by construction");
            let r = self.levels[h].get(n - 1).expect("just appended");
            if self.levels.len() == h + 1 {
                self.levels.push(Level::default());
            }
            self.levels[h + 1].v.push(node_hash(&l, &r));
            h += 1;
        }
        idx
    }

    pub fn append(&mut self, entry: &[u8]) -> u64 {
        self.append_leaf_hash(leaf_hash(entry))
    }

    pub fn leaf(&self, i: u64) -> Option<Hash> {
        self.levels.first()?.get(i)
    }

    /// `MTH(D[start .. start+n])`, or `None` if that needs a pruned node.
    fn mth(&self, start: u64, n: u64) -> Option<Hash> {
        if n == 0 {
            return Some(empty_root());
        }
        if n.is_power_of_two() && start % n == 0 {
            return self.levels.get(n.trailing_zeros() as usize)?.get(start / n);
        }
        let k = split(n);
        Some(node_hash(&self.mth(start, k)?, &self.mth(start + k, n - k)?))
    }

    /// Root of the first `size` leaves (`size <= self.size()`).
    pub fn root_at(&self, size: u64) -> Option<Hash> {
        if size > self.size() {
            return None;
        }
        self.mth(0, size)
    }

    pub fn root(&self) -> Hash {
        self.root_at(self.size()).expect("own root is always retained")
    }

    /// Inclusion proof for leaf `index` in the tree of the first `size` leaves.
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Option<Vec<Hash>> {
        if size > self.size() || index >= size {
            return None;
        }
        let mut out = Vec::new();
        self.path(index, 0, size, &mut out)?;
        Some(out)
    }

    // PATH(m, D[start..start+n]) appended bottom-up.
    fn path(&self, m: u64, start: u64, n: u64, out: &mut Vec<Hash>) -> Option<()> {
        if n <= 1 {
            return Some(());
        }
        let k = split(n);
        if m < k {
            self.path(m, start, k, out)?;
            out.push(self.mth(start + k, n - k)?);
        } else {
            self.path(m - k, start + k, n - k, out)?;
            out.push(self.mth(start, k)?);
        }
        Some(())
    }

    /// Consistency proof between the tree of the first `first` leaves and the
    /// tree of the first `second` leaves.  O(log n) hashes.
    pub fn consistency_proof(&self, first: u64, second: u64) -> Option<Vec<Hash>> {
        if first > second || second > self.size() {
            return None;
        }
        let mut out = Vec::new();
        if first != 0 && first != second {
            self.subproof(first, 0, second, true, &mut out)?;
        }
        Some(out)
    }

    fn subproof(&self, m: u64, start: u64, n: u64, b: bool, out: &mut Vec<Hash>) -> Option<()> {
        if m == n {
            if !b {
                out.push(self.mth(start, n)?);
            }
            return Some(());
        }
        let k = split(n);
        if m <= k {
            self.subproof(m, start, k, b, out)?;
            out.push(self.mth(start + k, n - k)?);
        } else {
            self.subproof(m - k, start + k, n - k, false, out)?;
            out.push(self.mth(start, k)?);
        }
        Some(())
    }
}

/// Verify an inclusion proof (RFC 9162 §2.1.3.2).  Fail closed.
pub fn verify_inclusion(leaf: &Hash, index: u64, size: u64, path: &[Hash], root: &Hash) -> bool {
    if index >= size {
        return false;
    }
    let (mut fnn, mut sn) = (index, size - 1);
    let mut r = *leaf;
    for p in path {
        if sn == 0 {
            return false;
        }
        if fnn & 1 == 1 || fnn == sn {
            r = node_hash(p, &r);
            if fnn & 1 == 0 {
                while fnn & 1 == 0 && fnn != 0 {
                    fnn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    sn == 0 && &r == root
}

/// Verify a consistency proof (RFC 9162 §2.1.4.2).  Fail closed.
pub fn verify_consistency(first: u64, first_root: &Hash, second: u64, second_root: &Hash, proof: &[Hash]) -> bool {
    if first > second {
        return false;
    }
    if first == second {
        return proof.is_empty() && first_root == second_root;
    }
    if first == 0 {
        // The empty tree is a prefix of everything; nothing to prove.
        return proof.is_empty() && *first_root == empty_root();
    }
    let mut p: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        p.push(*first_root);
    }
    p.extend_from_slice(proof);
    if p.is_empty() {
        return false;
    }
    let (mut fnn, mut sn) = (first - 1, second - 1);
    while fnn & 1 == 1 {
        fnn >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (p[0], p[0]);
    for c in &p[1..] {
        if sn == 0 {
            return false;
        }
        if fnn & 1 == 1 || fnn == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fnn & 1 == 0 {
                while fnn & 1 == 0 && fnn != 0 {
                    fnn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    &fr == first_root && &sr == second_root && sn == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(n: u64) -> Tree {
        let mut t = Tree::new();
        for i in 0..n {
            t.append(format!("entry-{i}").as_bytes());
        }
        t
    }

    /// Reference implementation straight from the RFC definition.
    fn naive(leaves: &[Hash]) -> Hash {
        match leaves.len() {
            0 => empty_root(),
            1 => leaves[0],
            n => {
                let k = split(n as u64) as usize;
                node_hash(&naive(&leaves[..k]), &naive(&leaves[k..]))
            }
        }
    }

    #[test]
    fn root_matches_reference_for_every_size() {
        let t = build(70);
        let leaves: Vec<Hash> = (0..70).map(|i| t.leaf(i).unwrap()).collect();
        for n in 0..=70u64 {
            assert_eq!(t.root_at(n).unwrap(), naive(&leaves[..n as usize]), "size {n}");
        }
        assert_eq!(build(0).root(), empty_root());
    }

    #[test]
    fn every_inclusion_proof_verifies_and_tampering_fails() {
        let t = build(40);
        for size in 1..=40u64 {
            let root = t.root_at(size).unwrap();
            for i in 0..size {
                let proof = t.inclusion_proof(i, size).unwrap();
                let lh = t.leaf(i).unwrap();
                assert!(verify_inclusion(&lh, i, size, &proof, &root), "{i}/{size}");
                // wrong leaf, wrong index, wrong root, truncated / extended path
                assert!(!verify_inclusion(&leaf_hash(b"x"), i, size, &proof, &root));
                assert!(!verify_inclusion(&lh, (i + 1) % size, size, &proof, &root) || size == 1);
                assert!(!verify_inclusion(&lh, i, size, &proof, &leaf_hash(b"r")));
                if !proof.is_empty() {
                    assert!(!verify_inclusion(&lh, i, size, &proof[1..], &root));
                    let mut longer = proof.clone();
                    longer.push([0u8; 32]);
                    assert!(!verify_inclusion(&lh, i, size, &longer, &root));
                }
            }
        }
    }

    #[test]
    fn every_consistency_proof_verifies_and_tampering_fails() {
        let t = build(40);
        for second in 0..=40u64 {
            for first in 0..=second {
                let proof = t.consistency_proof(first, second).unwrap();
                let (fr, sr) = (t.root_at(first).unwrap(), t.root_at(second).unwrap());
                assert!(verify_consistency(first, &fr, second, &sr, &proof), "{first}->{second}");
                if first != second {
                    // a forked history (different first root) must not verify
                    assert!(!verify_consistency(first, &leaf_hash(b"fork"), second, &sr, &proof));
                    // (the empty tree is a prefix of every tree, so first == 0 is vacuous in second_root)
                    if first != 0 {
                        assert!(!verify_consistency(first, &fr, second, &leaf_hash(b"fork"), &proof));
                    }
                    if !proof.is_empty() {
                        let mut bad = proof.clone();
                        bad[0][0] ^= 1;
                        assert!(!verify_consistency(first, &fr, second, &sr, &bad));
                    }
                }
            }
        }
        // shrinking is never consistent
        assert!(!verify_consistency(5, &t.root_at(5).unwrap(), 4, &t.root_at(4).unwrap(), &[]));
    }

    #[test]
    fn rewriting_history_is_detected() {
        // two logs that agree on 10 entries and then diverge
        let a = build(10);
        let mut b = build(10);
        b.append(b"fork-b");
        let mut a2 = a.clone();
        a2.append(b"fork-a");
        let p = a2.consistency_proof(10, 11).unwrap();
        assert!(verify_consistency(10, &a.root(), 11, &a2.root(), &p));
        assert!(!verify_consistency(10, &a.root(), 11, &b.root(), &p));
    }

    #[test]
    fn frontier_resume_matches_the_full_tree_for_every_join_point() {
        let full = build(70);
        for join in 0..=70u64 {
            let fr = full.frontier_at(join).unwrap();
            assert_eq!(fold_frontier(join, &fr), full.root_at(join), "fold at {join}");
            let mut t = Tree::from_frontier(join, &fr).unwrap();
            assert_eq!((t.size(), t.root()), (join, full.root_at(join).unwrap()));
            for i in join..70 {
                t.append(format!("entry-{i}").as_bytes());
                assert_eq!(t.root(), full.root_at(i + 1).unwrap(), "join {join} size {}", i + 1);
            }
            // a wrong-length frontier is refused
            assert!(Tree::from_frontier(join, &[[0; 32]; 70]).is_none());
        }
    }

    #[test]
    fn pruned_node_proves_backwards_in_log_n_without_history() {
        let full = build(1000);
        let join = 777u64;
        let mut t = Tree::from_frontier(join, &full.frontier_at(join).unwrap()).unwrap();
        for i in join..1000 {
            t.append(format!("entry-{i}").as_bytes());
        }
        let (old_root, new_root) = (full.root_at(join).unwrap(), full.root_at(1000).unwrap());
        // the pruned node proves its head extends the signed join point
        let p = t.consistency_proof(join, 1000).expect("join→head is retained");
        assert_eq!(p, full.consistency_proof(join, 1000).unwrap());
        assert!(verify_consistency(join, &old_root, 1000, &new_root, &p));
        // inclusion of entries since the join, against any later head
        for i in [join, 800, 999] {
            let ip = t.inclusion_proof(i, 1000).unwrap();
            assert!(verify_inclusion(&t.leaf(i).unwrap(), i, 1000, &ip, &new_root));
        }
        // history before the join is not retained
        assert!(t.leaf(0).is_none() && t.inclusion_proof(5, 1000).is_none());
        // memory: frontier + entries since join only
        assert!(t.retained_from() >= join - 1);
        // …and anyone holding only the NEW root can verify ANY older root with
        // a proof of at most 2·⌈log2 n⌉ hashes — cost grows with log n, not n.
        let bound = 2 * (64 - 1000u64.leading_zeros() as usize);
        for old in 1..=1000u64 {
            let proof = full.consistency_proof(old, 1000).unwrap();
            assert!(proof.len() <= bound, "{old}: {} > {bound}", proof.len());
            assert!(verify_consistency(old, &full.root_at(old).unwrap(), 1000, &new_root, &proof));
        }
    }
}
