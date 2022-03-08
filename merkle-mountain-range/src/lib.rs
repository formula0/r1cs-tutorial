#![allow(clippy::needless_range_loop)]

/// Defines a trait to chain two types of CRHs.
use ark_crypto_primitives::crh::TwoToOneCRHScheme;
use ark_crypto_primitives::{CRHScheme, Error};
use ark_ff::ToBytes;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::borrow::Borrow;
use ark_std::hash::Hash;
use ark_std::vec::Vec;

#[cfg(test)]
mod tests;

#[cfg(feature = "r1cs")]
pub mod constraints;
pub mod error;

pub use error::{Error, Result};

#[macro_use]
extern crate ark_std;

#[macro_use]
extern crate derivative;
mod macros;


/// Convert the hash digest in different layers by converting previous layer's output to
/// `TargetType`, which is a `Borrow` to next layer's input.
pub trait DigestConverter<From, To: ?Sized> {
    type TargetType: Borrow<To>;
    fn convert(item: From) -> Result<Self::TargetType, Error>;
}

/// A trivial converter where digest of previous layer's hash is the same as next layer's input.
pub struct IdentityDigestConverter<T> {
    _prev_layer_digest: T,
}

impl<T> DigestConverter<T, T> for IdentityDigestConverter<T> {
    type TargetType = T;
    fn convert(item: T) -> Result<T, Error> {
        Ok(item)
    }
}

/// Convert previous layer's digest to bytes and use bytes as input for next layer's digest.
/// TODO: `ToBytes` trait will be deprecated in future versions.
pub struct ByteDigestConverter<T: CanonicalSerialize + ToBytes> {
    _prev_layer_digest: T,
}

impl<T: CanonicalSerialize + ToBytes> DigestConverter<T, [u8]> for ByteDigestConverter<T> {
    type TargetType = Vec<u8>;

    fn convert(item: T) -> Result<Self::TargetType, Error> {
        // TODO: In some tests, `serialize` is not consistent with constraints. Try fix those.
        Ok(crate::to_unchecked_bytes!(item)?)
    }
}

/// Merkle tree have three types of hashes.
/// * `LeafHash`: Convert leaf to leaf digest
/// * `TwoLeavesToOneHash`: Convert two leaf digests to one inner digest. This one can be a wrapped
/// version `TwoHashesToOneHash`, which first converts leaf digest to inner digest.
/// * `TwoHashesToOneHash`: Compress two inner digests to one inner digest
pub trait Config {
    type Leaf: ?Sized; // merkle tree does not store the leaf
                       // leaf layer
    type LeafDigest: ToBytes
        + Clone
        + Eq
        + core::fmt::Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize;
    // transition between leaf layer to inner layer
    type LeafInnerDigestConverter: DigestConverter<
        Self::LeafDigest,
        <Self::TwoToOneHash as TwoToOneCRHScheme>::Input,
    >;
    // inner layer
    type InnerDigest: ToBytes
        + Clone
        + Eq
        + core::fmt::Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize;

    // Tom's Note: in the future, if we want different hash function, we can simply add more
    // types of digest here and specify a digest converter. Same for constraints.

    /// leaf -> leaf digest
    /// If leaf hash digest and inner hash digest are different, we can create a new
    /// leaf hash which wraps the original leaf hash and convert its output to `Digest`.
    type LeafHash: CRHScheme<Input = Self::Leaf, Output = Self::LeafDigest>;
    /// 2 inner digest -> inner digest
    type TwoToOneHash: TwoToOneCRHScheme<Output = Self::InnerDigest>;
}

pub type TwoToOneParam<P> = <<P as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters;
pub type LeafParam<P> = <<P as Config>::LeafHash as CRHScheme>::Parameters;

/// Stores the hashes of a particular path (in order) from root to leaf.
/// For example:
/// ```tree_diagram
///         [A]
///        /   \
///      [B]    C
///     / \   /  \
///    D [E] F    H
///   .. / \ ....
///    [I] J
/// ```
///  Suppose we want to prove I, then `leaf_sibling_hash` is J, `auth_path` is `[C,D]`
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Clone(bound = "P: Config"),
    Debug(bound = "P: Config"),
    Default(bound = "P: Config")
)]
pub struct Path<P: Config> {
    pub leaf_sibling_hash: P::LeafDigest,
    /// The sibling of path node ordered from higher layer to lower layer (does not include root node).
    pub auth_path: Vec<P::InnerDigest>,
    /// stores the leaf index of the node
    pub leaf_index: usize,
}

impl<P: Config> Path<P> {
    /// The position of on_path node in `leaf_and_sibling_hash` and `non_leaf_and_sibling_hash_path`.
    /// `position[i]` is 0 (false) iff `i`th on-path node from top to bottom is on the left.
    ///
    /// This function simply converts `self.leaf_index` to boolean array in big endian form.
    #[allow(unused)] // this function is actually used when r1cs feature is on

    // TODO : edit this function to mmr version

    fn position_list(&'_ self) -> impl '_ + Iterator<Item = bool> {
        (0..self.auth_path.len() + 1)
            .map(move |i| ((self.leaf_index >> i) & 1) != 0)
            .rev()
    }
}

impl<P: Config> Path<P> {

    pub fn new(leaf_sibling_hashe: P::LeafDigest, auth_path: Vec<P::InnerDigest>, leaf_index: usize) -> Self {
        Path {
            leaf_sibling_hash,
            auth_path,
            leaf_index,
        }
    }

    /// Verify that a leaf is at `self.index` of the merkle tree.
    /// * `leaf_size`: leaf size in number of bytes
    ///
    /// `verify` infers the tree height by setting `tree_height = self.auth_path.len() + 2`
    pub fn verify<L: Borrow<P::Leaf>>(
        &self,
        leaf_hash_params: &LeafParam<P>,
        two_to_one_params: &TwoToOneParam<P>,
        root_hash: &P::InnerDigest,
        leaf: L,
    ) -> Result<bool, crate::Error> {
        // calculate leaf hash
        // let claimed_leaf_hash = P::LeafHash::evaluate(&leaf_hash_params, leaf)?;
        // // check hash along the path from bottom to root
        // let (left_child, right_child) =
        //     select_left_right_child(self.leaf_index, &claimed_leaf_hash, &self.leaf_sibling_hash)?;

        // // leaf layer to inner layer conversion
        // let left_child = P::LeafInnerDigestConverter::convert(left_child)?;
        // let right_child = P::LeafInnerDigestConverter::convert(right_child)?;

        // let mut curr_path_node =
        //     P::TwoToOneHash::evaluate(&two_to_one_params, left_child, right_child)?;

        // // we will use `index` variable to track the position of path
        // let mut index = self.leaf_index;
        // index >>= 1;

        // // Check levels between leaf level and root
        // for level in (0..self.auth_path.len()).rev() {
        //     // check if path node at this level is left or right
        //     let (left, right) =
        //         select_left_right_child(index, &curr_path_node, &self.auth_path[level])?;
        //     // update curr_path_node
        //     curr_path_node = P::TwoToOneHash::compress(&two_to_one_params, &left, &right)?;
        //     index >>= 1;
        // }

        // // check if final hash is root
        // if &curr_path_node != root_hash {
        //     return Ok(false);
        // }

        // Ok(true)
    }
}

/// `index` is the first `path.len()` bits of
/// the position of tree.
///
/// If the least significant bit of `index` is 0, then `sibling` will be left and `computed` will be right.
/// Otherwise, `sibling` will be right and `computed` will be left.
///
/// Returns: (left, right)
fn select_left_right_child<L: Clone>(
    index: usize,
    computed_hash: &L,
    sibling_hash: &L,
) -> Result<(L, L), crate::Error> {
    // let is_left = index & 1 == 0;
    // let mut left_child = computed_hash;
    // let mut right_child = sibling_hash;
    // if !is_left {
    //     core::mem::swap(&mut left_child, &mut right_child);
    // }
    // Ok((left_child.clone(), right_child.clone()))
}

/// Defines a merkle tree data structure.
/// This merkle tree has runtime fixed height, and assumes number of leaves is 2^height.
///
/// TODO: add RFC-6962 compatible merkle tree in the future.
/// For this release, padding will not be supported because of security concerns: if the leaf hash and two to one hash uses same underlying
/// CRH, a malicious prover can prove a leaf while the actual node is an inner node. In the future, we can prefix leaf hashes in different layers to
/// solve the problem.
#[derive(Derivative)]
#[derivative(Clone(bound = "P: Config"))]
pub struct MerkleMountainRange<P: Config> {
    // /// stores the non-leaf nodes in level order. The first element is the root node.
    // /// The ith nodes (starting at 1st) children are at indices `2*i`, `2*i+1`
    // non_leaf_nodes: Vec<P::InnerDigest>,
    // /// store the hash of leaf nodes from left to right
    // leaf_nodes: Vec<P::LeafDigest>,
    batch: Vec<(usize, Vec<P::InnerDigest, P::LeafDigest>)>,
    /// Store the inner hash parameters
    two_to_one_hash_param: TwoToOneParam<P>,
    /// Store the leaf hash parameters
    leaf_hash_param: LeafParam<P>,
    /// Stores the size of the MerkleMountainRange
    mmr_size: usize,
}

impl<P: Config> MerkleMountainRange<P> {
    /// Create an empty merkle tree such that all leaves are zero-filled.
    /// Consider using a sparse merkle tree if you need the tree to be low memory
    pub fn blank(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
    ) -> Result<Self, crate::Error> {
        
        MerkleMountainRange {
            batch: vec![],
            leaf_hash_param,
            two_to_one_hash_param,
            mmr_size: 0
        }
    }

    /// Returns a new merkle tree. `leaves.len()` should be power of two.
    pub fn new<L: Borrow<P::Leaf>>(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        leaves: impl IntoIterator<Item = L>,
    ) -> Result<Self, crate::Error> {
        let mut leaves_digests = Vec::new();

        // compute and store hash values for each leaf
        // for leaf in leaves.into_iter() {
        //     let leaf_digest = P::LeafHash::evaluate(leaf_hash_param, leaf)?;
        //     Self::new_with_leaf(leaf_hash_param, two_to_one_hash_param, leaves_digest)
        // }
    }

    pub fn new_with_leaf(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        elem: P::LeafDigest
    ) -> Result<usize, crate::Error> {
        // let mut elems: Vec<P::LeafDigest, P::LeafDigest> = Vec::new();
        // // position of new elem
        // let elem_pos = self.mmr_size;
        // elems.push(elem);
        // let mut height = 0u32;
        // let mut pos = elem_pos;
        // let next_height = pos_height_in_tree(pos + 1);
        // // continue to merge tree node if next pos heigher than current
        // while next_height > height {
        //     pos += 1;
        //     let left_pos = pos - parent_offset(height);
        //     let right_pos = left_pos + sibling_offset(height);
        //     let mut left_elem = self.find_elem(left_pos, &elems)?;
        //     let mut right_elem = self.find_elem(right_pos, &elems)?;

        //     if (next_height == 2) {
        //         left_elem = P::LeafInnerDigestConverter::convert(left_elem);
        //         right_elem = P::LeafInnerDigestConverter::convert(right_elem);
        //     }

        //     let parent_elem = P::TwoToOneHash::compress(&two_to_one_hash_param, &left_elem, &right_elem);
        //     elems.push(parent_elem);
        //     height += 1
        // }
        // // store hashes
        // self.batch.push(elem_pos, elems);
        // // update mmr_size
        // self.mmr_size = pos + 1;

        // Ok(elem_pos)       
    }

    fn find_elem<'b>(&self, pos: usize, hashes: &'b [P::LeafDigest]) -> Result<borrow::Cow<'b, P::LeafDigest, P::LeafDigest>> {
        // let pos_offset = pos.checked_sub(self.mmr_size);
        // if let Some(elem) = pos_offset.and_then(|i| hashes.get(i as usize)) {
        //     return Ok(Cow::Borrowed(elem));
        // }
        // let elem = self.get_elem(pos as u64)?.ok_or(Error::InconsistentStore)?;
        // Ok(Cow::Owned(elem))
    }

    pub fn get_elem(&self, pos: u64) -> Result<Option<Elem>> {
        // for (start_pos, elems) in self.batch.iter().rev() {
        //     if pos < *start_pos {
        //         continue;
        //     } else if pos < start_pos + elems.len() as u64 {
        //         return Ok(elems.get((pos - start_pos) as usize).cloned());
        //     } else {
        //         break;
        //     }
        // }
    }

    /// Returns the root of the Merkle mountain range.
    pub fn root(&self) -> P::InnerDigest {
        // if self.mmr_size == 0 {
        //     return Err(Error::GetRootOnEmpty);
        // } else if self.mmr_size == 1 {
        //     return self.get_elem(0)?.ok_or(Error::InconsistentStore);
        // }
        // let peaks: Vec<T> = get_peaks(self.mmr_size)
        //     .into_iter()
        //     .map(|peak_pos| {
        //         self.batch
        //             .get_elem(peak_pos)
        //             .and_then(|elem| elem.ok_or(Error::InconsistentStore))
        //     })
        //     .collect::<Result<Vec<T>>>()?;
        // self.bag_rhs_peaks(peaks)?.ok_or(Error::InconsistentStore)
    }

    pub fn bag_rhs_peaks(&self, mut rhs_peaks: Vec<T>) -> Result<Option<P::InnerDigest>> {
        // println!("rhs_peaks: {:#?}", rhs_peaks);
        // while rhs_peaks.len() > 1 {
        //     let right_peak = rhs_peaks.pop().expect("pop");
        //     let left_peak = rhs_peaks.pop().expect("pop");
        //     rhs_peaks.push(P::TwoToOneHash::compress(&self.two_to_one_hash_param, &right_peak, &left_peak));
        // }
        // Ok(rhs_peaks.pop())
    }


    /// Returns the height of the Merkle mountain range.
    pub fn mmr_size(&self) -> usize {
        self.mmr_size
    }

    /// Returns the authentication path from leaf at `index` to root.
    pub fn generate_proof(&self, pos_list: Vec<u64>) -> Result<Path<P>, crate::Error> {

        // if pos_list.is_empty() {
        //     return Err(Error::GenProofForInvalidLeaves);
        // }
        // if self.mmr_size == 1 && index == 0 {
        //     return Ok(Path::new(self.mmr_size, Vec::new()));
        // }
        // // ensure positions is sorted
        // let peaks = get_peaks(self.mmr_size);
        // let mut proof: Vec<T> = Vec::new();
        // // generate merkle proof for each peaks
        // let mut bagging_track = 0;
        // for peak_pos in peaks {
        //     let pos_list: Vec<_> = take_while_vec(&mut pos_list, |&pos| pos <= peak_pos);
        //     if pos_list.is_empty() {
        //         bagging_track += 1;
        //     } else {
        //         bagging_track = 0;
        //     }
        //     self.gen_proof_for_peak(&mut proof, pos_list, peak_pos)?;
        // }

        // // ensure no remain positions
        // if !pos_list.is_empty() {
        //     return Err(Error::GenProofForInvalidLeaves);
        // }

        // if bagging_track > 1 {
        //     let rhs_peaks = proof.split_off(proof.len() - bagging_track);
        //     proof.push(self.bag_rhs_peaks(rhs_peaks)?.expect("bagging rhs peaks"));
        // }

        // // Ok(MerkleProof::new(self.mmr_size, proof))

        // Ok(Path {
        //     leaf_index: index,
        //     auth_path: path,
        //     leaf_sibling_hash,
        // })
    }

    /// Given the index and new leaf, return the hash of leaf and an updated path in order from root to bottom non-leaf level.
    /// This does not mutate the underlying tree.
    fn updated_path<T: Borrow<P::Leaf>>(
        &self,
        index: usize,
        new_leaf: T,
    ) -> Result<(P::LeafDigest, Vec<P::InnerDigest>), crate::Error> {
        // calculate the hash of leaf
        // let new_leaf_hash: P::LeafDigest = P::LeafHash::evaluate(&self.leaf_hash_param, new_leaf)?;

        // // calculate leaf sibling hash and locate its position (left or right)
        // let (leaf_left, leaf_right) = if index & 1 == 0 {
        //     // leaf on left
        //     (&new_leaf_hash, &self.leaf_nodes[index + 1])
        // } else {
        //     (&self.leaf_nodes[index - 1], &new_leaf_hash)
        // };

        // // calculate the updated hash at bottom non-leaf-level
        // let mut path_bottom_to_top = Vec::with_capacity(self.height - 1);
        // {
        //     path_bottom_to_top.push(P::TwoToOneHash::evaluate(
        //         &self.two_to_one_hash_param,
        //         P::LeafInnerDigestConverter::convert(leaf_left.clone())?,
        //         P::LeafInnerDigestConverter::convert(leaf_right.clone())?,
        //     )?);
        // }

        // // then calculate the updated hash from bottom to root
        // let leaf_index_in_tree = convert_index_to_last_level(index, self.height);
        // let mut prev_index = parent(leaf_index_in_tree).unwrap();
        // while !is_root(prev_index) {
        //     let (left_child, right_child) = if is_left_child(prev_index) {
        //         (
        //             path_bottom_to_top.last().unwrap(),
        //             &self.non_leaf_nodes[sibling(prev_index).unwrap()],
        //         )
        //     } else {
        //         (
        //             &self.non_leaf_nodes[sibling(prev_index).unwrap()],
        //             path_bottom_to_top.last().unwrap(),
        //         )
        //     };
        //     let evaluated =
        //         P::TwoToOneHash::compress(&self.two_to_one_hash_param, left_child, right_child)?;
        //     path_bottom_to_top.push(evaluated);
        //     prev_index = parent(prev_index).unwrap();
        // }

        // debug_assert_eq!(path_bottom_to_top.len(), self.height - 1);
        // let path_top_to_bottom: Vec<_> = path_bottom_to_top.into_iter().rev().collect();
        // Ok((new_leaf_hash, path_top_to_bottom))
    }

    /// Update the leaf at `index` to updated leaf.
    /// ```tree_diagram
    ///         [A]
    ///        /   \
    ///      [B]    C
    ///     / \   /  \
    ///    D [E] F    H
    ///   .. / \ ....
    ///    [I] J
    /// ```
    /// update(3, {new leaf}) would swap the leaf value at `[I]` and cause a recomputation of `[A]`, `[B]`, and `[E]`.
    pub fn update(&mut self, index: usize, new_leaf: &P::Leaf) -> Result<(), crate::Error> {
        // assert!(index < self.leaf_nodes.len(), "index out of range");
        // let (updated_leaf_hash, mut updated_path) = self.updated_path(index, new_leaf)?;
        // self.leaf_nodes[index] = updated_leaf_hash;
        // let mut curr_index = convert_index_to_last_level(index, self.height);
        // for _ in 0..self.height - 1 {
        //     curr_index = parent(curr_index).unwrap();
        //     self.non_leaf_nodes[curr_index] = updated_path.pop().unwrap();
        // }
        // Ok(())
    }

    /// Update the leaf and check if the updated root is equal to `asserted_new_root`.
    ///
    /// Tree will not be modified if the check fails.
    pub fn check_update<T: Borrow<P::Leaf>>(
        &mut self,
        index: usize,
        new_leaf: &P::Leaf,
        asserted_new_root: &P::InnerDigest,
    ) -> Result<bool, crate::Error> {
        // let new_leaf = new_leaf.borrow();
        // assert!(index < self.leaf_nodes.len(), "index out of range");
        // let (updated_leaf_hash, mut updated_path) = self.updated_path(index, new_leaf)?;
        // if &updated_path[0] != asserted_new_root {
        //     return Ok(false);
        // }
        // self.leaf_nodes[index] = updated_leaf_hash;
        // let mut curr_index = convert_index_to_last_level(index, self.height);
        // for _ in 0..self.height - 1 {
        //     curr_index = parent(curr_index).unwrap();
        //     self.non_leaf_nodes[curr_index] = updated_path.pop().unwrap();
        // }
        // Ok(true)
    }
}

/// Returns the height of the tree, given the number of leaves.
pub fn leaf_index_to_pos(index: usize) -> usize {
    // mmr_size - H - 1, H is the height(intervals) of last peak
    leaf_index_to_mmr_size(index) - (index + 1).trailing_zeros() as usize - 1
}

pub fn leaf_index_to_mmr_size(index: usize) -> usize {
    // leaf index start with 0
    let leaves_count = index + 1;

    // the peak count(k) is actually the count of 1 in leaves count's binary representation
    let peak_count = leaves_count.count_ones() as usize;

    2 * leaves_count - peak_count
}

pub fn pos_height_in_tree(mut pos: usize) -> usize {
    pos += 1;
    fn all_ones(num: usize) -> bool {
        num != 0 && num.count_zeros() == num.leading_zeros()
    }
    fn jump_left(pos: usize) -> usize {
        let bit_length = 64 - pos.leading_zeros();
        let most_significant_bits = 1 << (bit_length - 1);
        pos - (most_significant_bits - 1)
    }

    while !all_ones(pos) {
        pos = jump_left(pos)
    }

    64 - pos.leading_zeros() - 1
}

pub fn parent_offset(height: usize) -> usize {
    2 << height
}

pub fn sibling_offset(height: usize) -> usize {
    (2 << height) - 1
}

pub fn get_peaks(mmr_size: usize) -> Vec<usize> {
    let mut pos_s = Vec::new();
    let (mut height, mut pos) = left_peak_height_pos(mmr_size);
    pos_s.push(pos);
    while height > 0 {
        let peak = match get_right_peak(height, pos, mmr_size) {
            Some(peak) => peak,
            None => break,
        };
        height = peak.0;
        pos = peak.1;
        pos_s.push(pos);
    }
    pos_s
}

fn get_right_peak(mut height: usize, mut pos: usize, mmr_size: usize) -> Option<(usize, usize)> {
    // move to right sibling pos
    pos += sibling_offset(height);
    // loop until we find a pos in mmr
    while pos > mmr_size - 1 {
        if height == 0 {
            return None;
        }
        // move to left child
        pos -= parent_offset(height - 1);
        height -= 1;
    }
    Some((height, pos))
}

fn get_peak_pos_by_height(height: usize) -> usize {
    (1 << (height + 1)) - 2
}

fn left_peak_height_pos(mmr_size: usize) -> (usize, usize) {
    let mut height = 1;
    let mut prev_pos = 0;
    let mut pos = get_peak_pos_by_height(height);
    while pos < mmr_size {
        height += 1;
        prev_pos = pos;
        pos = get_peak_pos_by_height(height);
    }
    (height - 1, prev_pos)
}
