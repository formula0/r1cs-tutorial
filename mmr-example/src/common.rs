use ark_r1cs_std::prelude::UInt8;
use mmr_crypto_primitives::crh::injective_map::PedersenTwoToOneCRHCompressor;
use mmr_crypto_primitives::crh::injective_map::constraints::PedersenTwoToOneCRHCompressorGadget;
use mmr_crypto_primitives::crh::constraints::CRHSchemeGadget;
use mmr_crypto_primitives::crh::{injective_map::constraints::{
    PedersenCRHCompressorGadget, TECompressorGadget,
}, MMRTwoToOneCRHSchemeGadget};
use mmr_crypto_primitives::crh::{
    injective_map::{PedersenCRHCompressor, TECompressor},
    pedersen,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use mmr_crypto_primitives::mmr::constraints::{ConfigGadget, BytesVarDigestConverter};

use crate::MerkleConfig;

pub type TwoToOneHash = PedersenTwoToOneCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;

// `WINDOW_SIZE * NUM_WINDOWS` = 2 * 256 bits = enough for hashing two outputs.
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 128;
}

pub type LeafHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, LeafWindow>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LeafWindow;

// `WINDOW_SIZE * NUM_WINDOWS` = 2 * 256 bits = enough for hashing two outputs.
impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 144;
}

pub type TwoToOneHashGadget = PedersenTwoToOneCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    TwoToOneWindow,
    EdwardsVar,
    TECompressorGadget,
>;

pub type LeafHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    LeafWindow,
    EdwardsVar,
    TECompressorGadget,
>;

pub type LeafHashParamsVar = <LeafHashGadget as CRHSchemeGadget<LeafHash, ConstraintF>>::ParametersVar;
pub type TwoToOneHashParamsVar =
    <TwoToOneHashGadget as MMRTwoToOneCRHSchemeGadget<TwoToOneHash, ConstraintF>>::ParametersVar;

pub type ConstraintF = ark_ed_on_bls12_381::Fq;
type LeafVar<ConstraintF> = [UInt8<ConstraintF>];

pub struct JubJubMerkleMountainRangeParamsVar;
impl ConfigGadget<MerkleConfig, ConstraintF> for JubJubMerkleMountainRangeParamsVar {
    type Leaf = LeafVar<ConstraintF>;
    type LeafDigest = <LeafHashGadget as CRHSchemeGadget<LeafHash, ConstraintF>>::OutputVar;
    type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, ConstraintF>;
    type InnerDigest =
        <TwoToOneHashGadget as MMRTwoToOneCRHSchemeGadget<TwoToOneHash, ConstraintF>>::OutputVar;
    type LeafHash = LeafHashGadget;
    type TwoToOneHash = TwoToOneHashGadget;
}