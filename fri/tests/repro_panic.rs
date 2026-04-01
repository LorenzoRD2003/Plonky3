use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::{ExtensionMmcs, BatchOpening};
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, FriProof, QueryProof, CommitPhaseProofStep, verifier::verify_fri, TwoAdicFriFolding, CommitmentWithOpeningPoints};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_baby_bear::Poseidon2BabyBear;
use core::marker::PhantomData;
use p3_field::Field;
use rand::{SeedableRng, rngs::SmallRng};
use p3_field::coset::TwoAdicMultiplicativeCoset;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

fn setup_fri_params(fri_mmcs: ChallengeMmcs) -> FriParameters<ChallengeMmcs> {
    FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: fri_mmcs,
    }
}

#[test]
fn test_no_panic_underflow_bits_reduced() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
    let fri_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));

    let fri_params = setup_fri_params(fri_mmcs);

    let proof = FriProof {
        commit_phase_commits: vec![Default::default()],
        commit_pow_witnesses: vec![Val::ZERO],
        final_poly: vec![<Challenge as PrimeCharacteristicRing>::ZERO],
        query_pow_witness: <Val as PrimeCharacteristicRing>::ZERO,
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening {
                opened_values: vec![vec![<Val as PrimeCharacteristicRing>::ZERO]],
                opening_proof: Default::default(),
            }],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 1,
                sibling_values: vec![<Challenge as PrimeCharacteristicRing>::ZERO; 1],
                opening_proof: Default::default(),
            }],
        }],
    };

    let mut challenger = Challenger::new(perm);
    let folding = TwoAdicFriFolding::<Vec<BatchOpening<Val, ValMmcs>>, _>(PhantomData);

    let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 4).unwrap();
    let commitments_with_opening_points: Vec<CommitmentWithOpeningPoints<Challenge, <ValMmcs as p3_commit::Mmcs<Val>>::Commitment, TwoAdicMultiplicativeCoset<Val>>> = vec![
        (
            Default::default(),
            vec![(domain, vec![])]
        )
    ];

    let result = verify_fri::<_, Val, Challenge, ValMmcs, ChallengeMmcs, Challenger>(
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
fn test_no_panic_sample_bits_too_large() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
    let fri_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));

    let fri_params = setup_fri_params(fri_mmcs);

    let proof = FriProof {
        commit_phase_commits: vec![Default::default()],
        commit_pow_witnesses: vec![Val::ZERO],
        final_poly: vec![<Challenge as PrimeCharacteristicRing>::ZERO],
        query_pow_witness: <Val as PrimeCharacteristicRing>::ZERO,
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening {
                opened_values: vec![vec![<Val as PrimeCharacteristicRing>::ZERO]],
                opening_proof: Default::default(),
            }],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 31,
                sibling_values: vec![],
                opening_proof: Default::default(),
            }],
        }],
    };

    let mut challenger = Challenger::new(perm);
    let folding = TwoAdicFriFolding::<Vec<BatchOpening<Val, ValMmcs>>, _>(PhantomData);

    let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 1).unwrap();
    let commitments_with_opening_points: Vec<CommitmentWithOpeningPoints<Challenge, <ValMmcs as p3_commit::Mmcs<Val>>::Commitment, TwoAdicMultiplicativeCoset<Val>>> = vec![
        (
            Default::default(),
            vec![(domain, vec![])]
        )
    ];

    let result = verify_fri::<_, Val, Challenge, ValMmcs, ChallengeMmcs, Challenger>(
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
fn test_err_invalid_arity_zero() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
    let fri_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));

    let fri_params = setup_fri_params(fri_mmcs);

    let proof = FriProof {
        commit_phase_commits: vec![Default::default()],
        commit_pow_witnesses: vec![Val::ZERO],
        final_poly: vec![<Challenge as PrimeCharacteristicRing>::ZERO],
        query_pow_witness: <Val as PrimeCharacteristicRing>::ZERO,
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening {
                opened_values: vec![vec![<Val as PrimeCharacteristicRing>::ZERO]],
                opening_proof: Default::default(),
            }],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 0,
                sibling_values: vec![],
                opening_proof: Default::default(),
            }],
        }],
    };

    let mut challenger = Challenger::new(perm);
    let folding = TwoAdicFriFolding::<Vec<BatchOpening<Val, ValMmcs>>, _>(PhantomData);

    let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 1).unwrap();
    let commitments_with_opening_points: Vec<CommitmentWithOpeningPoints<Challenge, <ValMmcs as p3_commit::Mmcs<Val>>::Commitment, TwoAdicMultiplicativeCoset<Val>>> = vec![
        (
            Default::default(),
            vec![(domain, vec![])]
        )
    ];

    let result = verify_fri::<_, Val, Challenge, ValMmcs, ChallengeMmcs, Challenger>(
        &folding,
        &fri_params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &val_mmcs,
    );
    assert!(result.is_err());
}
