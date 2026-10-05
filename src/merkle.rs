use sha2::{self, Digest, Sha256};

/// A 32 byte SHA-256 digest.
pub type Hash = [u8; 32];

/// The all zero digest.
pub const ZERO_HASH: Hash = [0u8; 32];

pub(crate) fn hash256(data: &[u8]) -> Hash {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

// domain tags separating the two kinds of preimage in the tree. Hashing both
// alike lets an internal node's 64 bytes be passed off as a transaction, which
// forges an inclusion proof; RFC 6962 keeps them apart by tagging
const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;

/// Hashes a transaction's bytes into a leaf of the tree.
pub(crate) fn hash_leaf(data: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(1 + data.len());

    buf.push(LEAF_TAG);
    buf.extend_from_slice(data);

    hash256(buf.as_slice())
}

/// Combines two child hashes into the parent hash.
fn hash_children(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 1 + 32 + 32];

    buf[0] = NODE_TAG;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);

    hash256(&buf)
}

/// Which side of a pair a sibling sits on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Side {
    /// The sibling is the left child, so it is hashed first.
    Left,
    /// The sibling is the right child, so it is hashed second.
    Right,
}

/// The sibling hashes, ordered from the leaf upwards, that recompute a Merkle
/// root from a single leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    path: Vec<(Hash, Side)>,
}

impl MerkleProof {
    /// Returns `true` if `leaf` combined with the path reproduces `root`.
    pub fn verify(&self, leaf: Hash, root: Hash) -> bool {
        let mut node = leaf;

        for (sib, side) in self.path.iter() {
            // hash output depends on order of concatenation
            node = match side {
                Side::Left => hash_children(sib, &node),
                Side::Right => hash_children(&node, sib),
            }
        }

        node == root
    }

    /// Returns the number of combine steps the proof replays.
    pub fn len(&self) -> usize {
        self.path.len()
    }

    /// Returns `true` if the proof replays no steps.
    pub fn is_empty(&self) -> bool {
        self.path.is_empty()
    }
}

/// A Merkle tree over a set of leaf hashes, held level by level from the
/// leaves up to the root.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Hash Nodes structured as a Merkle Tree.
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Builds the tree over `leaves`.
    ///
    /// Returns `None` if `leaves` is empty.
    pub fn new(leaves: Vec<Hash>) -> Option<Self> {
        if leaves.is_empty() {
            return None;
        }

        let mut levels = vec![leaves];

        // build the tree bottoms-up until root found, starting from the leaves
        // each new level is derived from highest/latest level in the vec
        while let Some(lvl) = levels.last() {
            // root node found
            if lvl.len() <= 1 {
                break;
            }

            // 1. concatenate each pair of hashes
            // 2. hash the output to get parent hash
            let new_lvl = lvl
                .chunks(2)
                .map(|nodes| match nodes {
                    [left, right] => hash_children(left, right),
                    // CVE-2012-2459: an odd level's last node is promoted to upper level
                    [left] => *left,
                    _ => unreachable!("chunks(2) yields 1 or 2 nodes"),
                })
                .collect();

            levels.push(new_lvl);
        }

        Some(Self { levels })
    }

    /// Returns the Merkle root.
    pub fn root(&self) -> Hash {
        *self
            .levels
            .last()
            .and_then(|lvl| lvl.first())
            .expect("levels is non-empty and ends in a single node")
    }

    /// Returns the leaves the tree was built over, in their original order.
    pub fn leaves(&self) -> &[Hash] {
        // leaves always exist so indexing is fine here
        &self.levels[0]
    }

    /// Constructs a `MerkleProof` of the sibling hashes needed to reach the
    /// root from the leaf at `index`.
    ///
    /// Returns `None` if `index` is past the last leaf.
    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        // check for leaf
        if index >= self.leaves().len() {
            return None;
        }

        let mut path = Vec::with_capacity(self.levels.len() - 1);
        // a level of n nodes yields ceil(n / 2) parents once pairs are combined
        // and a lone trailing node is promoted, so the node at `pos` sits at
        // `pos / 2` in the level above
        let mut pos = index;

        // leaves -> root traversal, building a path of sibling hashes along the way
        // time comp: O(height) where height = log N
        // explanation: search space keeps halving and O(1) work per level
        for lvl in &self.levels[..self.levels.len() - 1] {
            let (sibling_pos, side) = if pos.is_multiple_of(2) {
                // left node of a pair, return right sibling info
                (pos + 1, Side::Right)
            } else {
                // right node of a pair, return left sibling info
                (pos - 1, Side::Left)
            };

            // retrieve sibling hash
            if let Some(hash) = lvl.get(sibling_pos) {
                path.push((*hash, side))
            }

            pos /= 2
        }

        Some(MerkleProof { path })
    }
}

/// Builds a `MerkleTree` over `leaves` and returns its root.
///
/// Returns `None` if `leaves` is empty.
pub fn to_merkle_root(leaves: Vec<Hash>) -> Option<Hash> {
    MerkleTree::new(leaves).map(|tree| tree.root())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| hash256(&[i as u8])).collect()
    }

    fn pair(left: Hash, right: Hash) -> Hash {
        let mut buf = [0u8; 1 + 32 + 32];
        buf[0] = NODE_TAG;
        buf[1..33].copy_from_slice(&left);
        buf[33..].copy_from_slice(&right);
        hash256(&buf)
    }

    #[test]
    fn a_node_preimage_is_not_a_leaf_preimage() {
        let l = leaves(2);

        let mut node_bytes = [0u8; 32 + 32];
        node_bytes[..32].copy_from_slice(&l[0]);
        node_bytes[32..].copy_from_slice(&l[1]);

        assert_ne!(hash_leaf(&node_bytes), hash_children(&l[0], &l[1]));
    }

    #[test]
    fn merkle_root_from_even_leaves() {
        let l = leaves(4);
        let expected = pair(pair(l[0], l[1]), pair(l[2], l[3]));

        assert_eq!(to_merkle_root(l), Some(expected));
    }

    #[test]
    fn merkle_root_from_odd_leaves() {
        // the lone trailing leaf is promoted to the next level unchanged
        let l = leaves(3);
        let expected = pair(pair(l[0], l[1]), l[2]);

        assert_eq!(to_merkle_root(l), Some(expected));
    }

    #[test]
    fn merkle_root_of_no_leaves_is_none() {
        assert_eq!(to_merkle_root(Vec::new()), None);
        assert!(MerkleTree::new(Vec::new()).is_none());
    }

    #[test]
    fn merkle_root_of_a_single_leaf_is_that_leaf() {
        let l = leaves(1);

        assert_eq!(to_merkle_root(l.clone()), Some(l[0]));
    }

    #[test]
    fn reordering_leaves_changes_the_root() {
        let l = leaves(4);
        let mut swapped = l.clone();
        swapped.swap(0, 1);

        assert_ne!(to_merkle_root(l), to_merkle_root(swapped));
    }

    #[test]
    fn duplicated_trailing_leaf_yields_a_different_root() {
        let three = leaves(3);
        let mut four = three.clone();
        four.push(three[2]);

        assert_ne!(to_merkle_root(three), to_merkle_root(four));
    }

    #[test]
    fn duplication_collision_does_not_recur_at_higher_levels() {
        let five = leaves(5);
        let mut eight = five.clone();
        eight.extend([five[4]; 3]);

        assert_ne!(to_merkle_root(five), to_merkle_root(eight));
    }

    #[test]
    fn the_tree_agrees_with_the_standalone_root() {
        for n in 1..=33 {
            let l = leaves(n);
            let tree = MerkleTree::new(l.clone()).unwrap();

            assert_eq!(Some(tree.root()), to_merkle_root(l), "n = {n}");
        }
    }

    #[test]
    fn every_leaf_proves_itself_against_the_root() {
        // sizes either side of each power of two, where promotion bites
        for n in 1..=33 {
            let l = leaves(n);
            let tree = MerkleTree::new(l.clone()).unwrap();

            for (i, leaf) in l.iter().enumerate() {
                let proof = tree.proof(i).expect("leaf i has a proof");

                assert!(proof.verify(*leaf, tree.root()), "n = {n}, leaf = {i}");
            }
        }
    }

    #[test]
    fn a_proof_is_logarithmic_in_the_number_of_leaves() {
        let tree = MerkleTree::new(leaves(1_000)).unwrap();
        let proof = tree.proof(0).unwrap();

        // ten combine steps stand in for the other 999 transactions
        assert_eq!(proof.len(), 10);
    }

    #[test]
    fn a_single_leaf_needs_no_path_at_all() {
        let l = leaves(1);
        let tree = MerkleTree::new(l.clone()).unwrap();
        let proof = tree.proof(0).unwrap();

        assert!(proof.is_empty());
        assert!(proof.verify(l[0], tree.root()));
    }

    #[test]
    fn a_proof_does_not_carry_a_leaf_that_is_not_in_the_tree() {
        let l = leaves(8);
        let tree = MerkleTree::new(l).unwrap();
        let proof = tree.proof(3).unwrap();

        let outsider = hash256(b"never mined");

        assert!(!proof.verify(outsider, tree.root()));
    }

    #[test]
    fn a_proof_for_one_leaf_does_not_verify_another() {
        let l = leaves(8);
        let tree = MerkleTree::new(l.clone()).unwrap();
        let proof = tree.proof(3).unwrap();

        assert!(proof.verify(l[3], tree.root()));
        assert!(!proof.verify(l[4], tree.root()));
    }

    #[test]
    fn a_tampered_path_stops_verifying() {
        let l = leaves(8);
        let tree = MerkleTree::new(l.clone()).unwrap();
        let mut proof = tree.proof(3).unwrap();

        proof.path[0].0 = hash256(b"forged sibling");

        assert!(!proof.verify(l[3], tree.root()));
    }

    #[test]
    fn flipping_a_side_stops_verifying() {
        // the sides are what fix a leaf's position; without them a proof
        // would attest to membership but not to where
        let l = leaves(8);
        let tree = MerkleTree::new(l.clone()).unwrap();
        let mut proof = tree.proof(3).unwrap();

        proof.path[0].1 = match proof.path[0].1 {
            Side::Left => Side::Right,
            Side::Right => Side::Left,
        };

        assert!(!proof.verify(l[3], tree.root()));
    }

    #[test]
    fn there_is_no_proof_past_the_last_leaf() {
        let tree = MerkleTree::new(leaves(4)).unwrap();

        assert!(tree.proof(3).is_some());
        assert!(tree.proof(4).is_none());
    }

    #[test]
    fn a_promoted_leaf_skips_the_level_it_was_alone_on() {
        // three leaves: l[2] is promoted from level 0 to level 1, so its path
        // is one step shorter than its siblings' two
        let l = leaves(3);
        let tree = MerkleTree::new(l.clone()).unwrap();

        assert_eq!(tree.proof(0).unwrap().len(), 2);
        assert_eq!(tree.proof(1).unwrap().len(), 2);
        assert_eq!(tree.proof(2).unwrap().len(), 1);

        assert!(tree.proof(2).unwrap().verify(l[2], tree.root()));
    }
}
