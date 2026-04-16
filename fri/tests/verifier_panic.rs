use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::{BatchOpening, ExtensionMmcs};
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::verifier::verify_fri;
use p3_fri::{
    CommitPhaseProofStep, FriParameters, FriProof, QueryProof, TwoAdicFriFolding,
};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation, MerkleCap};
use std::marker::PhantomData;
use rand::SeedableRng;
use rand::rngs::SmallRng;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

#[test]
fn test_verify_fri_rejects_large_log_arity() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
    let fri_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));

    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: fri_mmcs,
    };

    let mut challenger = Challenger::new(perm);

    // Construct a proof with a very large log_arity (30 > TWO_ADICITY of BabyBear which is 27)
    let log_arity = 30;
    let proof = FriProof {
        commit_phase_commits: vec![MerkleCap::new(vec![[Val::ZERO; 8]])],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: log_arity as u8,
                sibling_values: vec![Challenge::ZERO; (1 << 2) - 1],
                opening_proof: Default::default(),
            }],
        }],
        final_poly: vec![Challenge::ZERO; 1],
        query_pow_witness: Val::ZERO,
    };

    let folding: TwoAdicFriFolding<Vec<BatchOpening<Val, ValMmcs>>, _> =
        TwoAdicFriFolding(PhantomData);

    let mut challenger = challenger;
    let result = verify_fri::<_, Val, Challenge, ValMmcs, ChallengeMmcs, Challenger>(
        &folding,
        &params,
        &proof,
        &mut challenger,
        &[], // commitments_with_opening_points
        &val_mmcs,
    );

    assert!(result.is_err(), "Expected verifier to return error on malformed log_arity");
}

#[test]
fn test_verify_fri_rejects_excessive_total_height() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
    let fri_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));

    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: fri_mmcs,
    };

    let mut challenger = Challenger::new(perm);

    // Construct a proof where total_log_reduction + log_blowup > Val::TWO_ADICITY
    let num_steps = 30;
    let log_arity = 1;
    let proof = FriProof {
        commit_phase_commits: vec![MerkleCap::new(vec![[Val::ZERO; 8]]); num_steps],
        commit_pow_witnesses: vec![Val::ZERO; num_steps],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![
                CommitPhaseProofStep {
                    log_arity: log_arity as u8,
                    sibling_values: vec![Challenge::ZERO; (1 << log_arity) - 1],
                    opening_proof: Default::default(),
                };
                num_steps
            ],
        }],
        final_poly: vec![Challenge::ZERO; 1],
        query_pow_witness: Val::ZERO,
    };

    let folding: TwoAdicFriFolding<Vec<BatchOpening<Val, ValMmcs>>, _> =
        TwoAdicFriFolding(PhantomData);

    let mut challenger = challenger;
    let result = verify_fri::<_, Val, Challenge, ValMmcs, ChallengeMmcs, Challenger>(
        &folding,
        &params,
        &proof,
        &mut challenger,
        &[],
        &val_mmcs,
    );

    assert!(result.is_err(), "Expected verifier to return error on excessive total height");
}
