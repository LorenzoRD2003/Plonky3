use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{DuplexChallenger};
use p3_commit::{ExtensionMmcs, BatchOpening};
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{
    CommitPhaseProofStep, FriParameters, FriProof, QueryProof, TwoAdicFriFolding,
};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::rngs::SmallRng;
use rand::SeedableRng;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

#[test]
fn test_repro_underflow_log_global_max_height() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
    let fri_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));

    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: fri_mmcs,
    };

    let mut challenger = Challenger::new(perm);

    // log_arity 1 => total_log_reduction = 1.
    // log_global_max_height = 1 + 1 + 0 = 2.
    // If we have an input matrix of log_height 2 (size 4),
    // its log_height after blowup is 2 + 1 = 3.
    // bits_reduced = log_global_max_height - log_height = 2 - 3 = underflow!

    let proof = FriProof {
        commit_phase_commits: vec![Default::default()],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening {
                opened_values: vec![vec![Val::ZERO]],
                opening_proof: Default::default(),
            }],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 1,
                sibling_values: vec![Challenge::ZERO],
                opening_proof: Default::default(),
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let domain = p3_field::coset::TwoAdicMultiplicativeCoset::new(Val::ONE, 2).unwrap();
    let commitments_with_opening_points = vec![
        (
            Default::default(), // mmcs commitment
            vec![(domain, vec![(Challenge::ZERO, vec![Challenge::ZERO])])],
        )
    ];

    let folding = TwoAdicFriFolding::<Vec<p3_commit::BatchOpening<Val, ValMmcs>>, _>(core::marker::PhantomData);

    let result = p3_fri::verifier::verify_fri(
        &folding,
        &fri_params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &val_mmcs,
    );
    assert!(result.is_err());
}

#[test]
fn test_repro_large_arity_panic() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
    let fri_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));

    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: fri_mmcs,
    };

    let mut challenger = Challenger::new(perm);

    let proof = FriProof {
        commit_phase_commits: vec![Default::default()],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 100, // Extremely large arity
                sibling_values: vec![Challenge::ZERO; 15],
                opening_proof: Default::default(),
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let commitments_with_opening_points = vec![];

    let folding = TwoAdicFriFolding::<Vec<p3_commit::BatchOpening<Val, ValMmcs>>, _>(core::marker::PhantomData);

    let result = p3_fri::verifier::verify_fri(
        &folding,
        &fri_params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &val_mmcs,
    );
    assert!(result.is_err());
}

#[test]
fn test_repro_zero_arity_panic() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
    let fri_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));

    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: fri_mmcs,
    };

    let mut challenger = Challenger::new(perm);

    let proof = FriProof {
        commit_phase_commits: vec![Default::default()],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 0, // Zero arity
                sibling_values: vec![],
                opening_proof: Default::default(),
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let commitments_with_opening_points = vec![];

    let folding = TwoAdicFriFolding::<Vec<p3_commit::BatchOpening<Val, ValMmcs>>, _>(core::marker::PhantomData);

    let result = p3_fri::verifier::verify_fri(
        &folding,
        &fri_params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &val_mmcs,
    );
    assert!(result.is_err());
}
