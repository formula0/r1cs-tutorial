use crate::common::*;
use crate::{Root, SimplePath};
use mmr_crypto_primitives::crh::{TwoToOneCRHSchemeGadget, CRHScheme, MMRTwoToOneCRHScheme};
use mmr_crypto_primitives::mmr::constraints::PathVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

// (You don't need to worry about what's going on in the next two type definitions,
// just know that these are types that you can use.)

/// The R1CS equivalent of the the Merkle mountain range root.
pub type RootVar = <TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, ConstraintF>>::OutputVar;

/// The R1CS equivalent of the the Merkle mountain range path.
pub type SimplePathVar =
    PathVar<crate::MerkleConfig, ConstraintF, JubJubMerkleMountainRangeParamsVar>;

////////////////////////////////////////////////////////////////////////////////

pub struct MerkleMountainRangeVerification {
    // These are constants that will be embedded into the circuit
    pub leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as MMRTwoToOneCRHScheme>::Parameters,

    // These are the public inputs to the circuit.
    pub root: Root,
    pub leaf: u8,

    // This is the private witness to the circuit.
    pub authentication_path: Option<SimplePath>,
}

impl ConstraintSynthesizer<ConstraintF> for MerkleMountainRangeVerification {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // First, we allocate the public inputs
        let root = RootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;

        let leaf = UInt8::new_input(ark_relations::ns!(cs, "leaf_var"), || Ok(&self.leaf))?;

        // Then, we allocate the public parameters as constants:
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // Finally, we allocate our path as a private witness variable:
        let path = SimplePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
            Ok(self.authentication_path.as_ref().unwrap())
        })?;

        let leaf_bytes = vec![leaf; 1];

        // Now, we have to check membership. How do we do that?
        // Hint: look at https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/constraints.rs#L135

        // TODO: FILL IN THE BLANK!
        let is_member = // TODO: FILL IN THE BLANK!
            path.verify_membership(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &leaf_bytes.as_slice(),
    )?;

    is_member.enforce_equal(&Boolean::TRUE)?;
        Ok(())
    }
}

// Run this test via `cargo test --release test_merkle_tree`.
#[test]
fn mmr_constraints_correctness() {
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as MMRTwoToOneCRHScheme>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
    let mut mmr = crate::SimpleMerkleMountainRange::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
    );

    let leaves = &vec![1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8];
    mmr.push_vec(leaves.iter().map(|x| [x.clone()])).unwrap();

    // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
    let proof = mmr.generate_proof(7).unwrap(); // we're 0-indexing!, 5th leaf position is 7
                                                 // This should be a proof for the membership of a leaf with value 9. Let's check that!

    // First, let's get the root we want to verify against:
    let root = mmr.get_root().unwrap();

    let circuit = MerkleMountainRangeVerification {
        // constants
        leaf_crh_params,
        two_to_one_crh_params,

        // public inputs
        root,
        leaf: 9u8,

        // witness
        authentication_path: Some(proof),
    };
    // First, some boilerplat that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Next, let's make the circuit!
    let cs = ConstraintSystem::new_ref();


    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    
    let is_satisfied = cs.is_satisfied().unwrap();

    if !is_satisfied {
        // If it isn't, find out the offending constraint.
        println!("{:?}", cs.which_is_unsatisfied());
    }
    assert!(is_satisfied);
}

// Run this test via `cargo test --release test_mmr_constraints_soundness`.
// This tests that a given invalid authentication path will fail.
#[test]
fn mmr_constraints_soundness() {
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as MMRTwoToOneCRHScheme>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
    let mut mmr = crate::SimpleMerkleMountainRange::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
    );

    let leaves = &vec![1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8];
    mmr.push_vec(leaves.iter().map(|x| [x.clone()])).unwrap();

    // We just mutate the first leaf
    let mut second_mmr = crate::SimpleMerkleMountainRange::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
    );

    let leaves = &vec![4u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8];
    second_mmr.push_vec(leaves.iter().map(|x| [x.clone()])).unwrap();

    // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
    let proof = mmr.generate_proof(7).unwrap(); // we're 0-indexing!, 5th leaf position is 7

    // But, let's get the root we want to verify against:
    let wrong_root = second_mmr.get_root().unwrap();

    let circuit = MerkleMountainRangeVerification {
        // constants
        leaf_crh_params,
        two_to_one_crh_params,

        // public inputs
        root: wrong_root,
        leaf: 9u8,

        // witness
        authentication_path: Some(proof),
    };
    // First, some boilerplate that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Next, let's make the constraint system!
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();
    // We expect this to fail!
    assert!(!is_satisfied);
}