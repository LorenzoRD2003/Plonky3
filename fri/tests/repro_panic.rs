use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{DuplexChallenger};
use p3_commit::{ExtensionMmcs, Pcs, BatchOpening};
use p3_dft::Radix2Dit;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs, FriProof, QueryProof, CommitPhaseProofStep};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::rngs::SmallRng;
use rand::{SeedableRng};

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;

type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type MyPcs = TwoAdicFriPcs<BabyBear, Radix2Dit<BabyBear>, ValMmcs, ChallengeMmcs>;

#[test]
fn test_log_global_max_height_mismatch_rejection() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let input_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
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
    let dft = Radix2Dit::default();
    let pcs = MyPcs::new(dft, input_mmcs, fri_params);

    let log_size = 5; // Verifier expects log_global_max_height = 5 + 1 = 6
    let deg = 1 << log_size;
    let domain = <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, deg);
    let evals = RowMajorMatrix::<Val>::rand(&mut rng, deg, 1);
    let (commitment, _prover_data) = <MyPcs as Pcs<Challenge, Challenger>>::commit(&pcs, [(domain, evals)]);

    // Prover provides log_arity that makes log_global_max_height = 1 + 1 + 0 = 2
    let proof = FriProof {
        commit_phase_commits: vec![Default::default()],
        commit_pow_witnesses: vec![Val::ZERO],
        final_poly: vec![Challenge::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening { opened_values: vec![], opening_proof: Default::default() }],
            commit_phase_openings: vec![CommitPhaseProofStep {
                sibling_values: vec![Challenge::ZERO],
                opening_proof: Default::default(),
                log_arity: 1,
            }],
        }],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = Challenger::new(perm);
    let commitments_with_opening_points = vec![(
        commitment,
        vec![(domain, vec![(Challenge::ZERO, vec![Challenge::ZERO])])],
    )];

    let result = <MyPcs as Pcs<Challenge, Challenger>>::verify(&pcs, commitments_with_opening_points, &proof, &mut challenger);
    assert!(result.is_err());
}

#[test]
fn test_log_max_height_too_large_rejection() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let input_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
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
    let dft = Radix2Dit::default();
    let pcs = MyPcs::new(dft, input_mmcs, fri_params);

    let log_size = 5;
    let deg = 1 << log_size;
    let domain = <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, deg);
    let evals = RowMajorMatrix::<Val>::rand(&mut rng, deg, 1);
    let (commitment, _prover_data) = <MyPcs as Pcs<Challenge, Challenger>>::commit(&pcs, [(domain, evals)]);

    // Prover provides log_arity that is too large
    let proof = FriProof {
        commit_phase_commits: vec![Default::default()],
        commit_pow_witnesses: vec![Val::ZERO],
        final_poly: vec![Challenge::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening { opened_values: vec![], opening_proof: Default::default() }],
            commit_phase_openings: vec![CommitPhaseProofStep {
                sibling_values: vec![Challenge::ZERO; (1 << 5) - 1],
                opening_proof: Default::default(),
                log_arity: 5,
            },
            CommitPhaseProofStep {
                sibling_values: vec![Challenge::ZERO; (1 << 25) - 1],
                opening_proof: Default::default(),
                log_arity: 25,
            }
            ],
        }],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = Challenger::new(perm);
    let commitments_with_opening_points = vec![(
        commitment,
        vec![(domain, vec![(Challenge::ZERO, vec![Challenge::ZERO])])],
    )];

    let result = <MyPcs as Pcs<Challenge, Challenger>>::verify(&pcs, commitments_with_opening_points, &proof, &mut challenger);
    assert!(result.is_err());
}

#[test]
fn test_zero_log_arity_rejection() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let input_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
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
    let dft = Radix2Dit::default();
    let pcs = MyPcs::new(dft, input_mmcs, fri_params);

    let log_size = 5;
    let deg = 1 << log_size;
    let domain = <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, deg);
    let evals = RowMajorMatrix::<Val>::rand(&mut rng, deg, 1);
    let (commitment, _prover_data) = <MyPcs as Pcs<Challenge, Challenger>>::commit(&pcs, [(domain, evals)]);

    // Prover provides zero log_arity
    let proof = FriProof {
        commit_phase_commits: vec![Default::default()],
        commit_pow_witnesses: vec![Val::ZERO],
        final_poly: vec![Challenge::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening { opened_values: vec![], opening_proof: Default::default() }],
            commit_phase_openings: vec![CommitPhaseProofStep {
                sibling_values: vec![],
                opening_proof: Default::default(),
                log_arity: 0,
            }],
        }],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = Challenger::new(perm);
    let commitments_with_opening_points = vec![(
        commitment,
        vec![(domain, vec![(Challenge::ZERO, vec![Challenge::ZERO])])],
    )];

    let result = <MyPcs as Pcs<Challenge, Challenger>>::verify(&pcs, commitments_with_opening_points, &proof, &mut challenger);
    assert!(result.is_err());
}
