use mmr_crypto_primitives::{mmr::{Config, MerkleMountainRange, Path, ByteDigestConverter}, crh::MMRTwoToOneCRHScheme, CRHScheme};

pub mod common;
use common::*;

mod constraints;
// mod constraints_test;

#[derive(Clone)]
pub struct MerkleConfig;
impl Config for MerkleConfig {
    // Our Merkle tree relies on two hashes: one to hash leaves, and one to hash pairs
    // of internal nodes.
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;

    type Leaf = [u8];

    type LeafDigest = <LeafHash as CRHScheme>::Output;

    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;

    type InnerDigest = <TwoToOneHash as MMRTwoToOneCRHScheme>::Output;
}

/// A Merkle tree containing account information.
pub type SimpleMerkleMountainRange = MerkleMountainRange<MerkleConfig>;
/// The root of the account Merkle tree.
pub type Root = <TwoToOneHash as MMRTwoToOneCRHScheme>::Output;
/// A membership proof for a given account.
pub type SimplePath = Path<MerkleConfig>;

// Run this test via `cargo test --release test_mmr`.
#[test]
fn test_mmr() {
    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as MMRTwoToOneCRHScheme>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle-mountain-range/mod.rs#L156
    let mut mmr = SimpleMerkleMountainRange::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
    );

    let leaves = &vec![1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8];
    mmr.push_vec(leaves.iter().map(|x| [x.clone()])).unwrap();

    // Now, let's try to generate a membership proof for the 5th item.
    let proof = mmr.generate_proof(7).unwrap(); // we're 0-indexing!
                                                 // This should be a proof for the membership of a leaf with value 9. Let's check that!

    // First, let's get the root we want to verify against:
    let root = mmr.get_root().unwrap();
    // Next, let's verify the proof!
    let result = proof
        .verify(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            [9u8], // The claimed leaf
        )
        .unwrap();
    assert!(result);
}
