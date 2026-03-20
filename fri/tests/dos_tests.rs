use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs, FriProof, QueryProof, CommitPhaseProofStep};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::SeedableRng;
use rand::rngs::SmallRng;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Radix2DitParallel<Val>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

#[test]
fn test_dos_large_log_arity() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };

    let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
    let mut challenger = Challenger::new(perm);

    // Create a dummy proof with a large log_arity
    let proof = FriProof {
        commit_phase_commits: vec![Default::default()],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 25, // Large arity
                sibling_values: vec![Challenge::ZERO; (1 << 25) - 1], // Provide enough siblings
                opening_proof: Default::default(),
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    // Use a small degree to pass sample_bits and avoid HUGE memory allocation in open_input if log_global_max_height were 100.
    let domain = <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, 1 << 4);
    let commitments_with_opening_points = vec![(
        Default::default(),
        vec![(domain, vec![(Challenge::ZERO, vec![Challenge::ZERO])])],
    )];

    // This should ideally return an error, but currently it might panic.
    let result = pcs.verify(commitments_with_opening_points, &proof, &mut challenger);

    // If we reached here, it didn't panic. Let's see if it returned an error.
    assert!(result.is_err());
}

#[test]
fn test_dos_zero_log_arity() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };

    let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
    let mut challenger = Challenger::new(perm);

    // Create a dummy proof with a zero log_arity
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

    let domain = <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, 1 << 4);
    let commitments_with_opening_points = vec![(
        Default::default(),
        vec![(domain, vec![(Challenge::ZERO, vec![Challenge::ZERO])])],
    )];

    let result = pcs.verify(commitments_with_opening_points, &proof, &mut challenger);
    assert!(result.is_err());
}

#[test]
fn test_dos_sum_log_arity_overflow() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 10,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };

    let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
    let mut challenger = Challenger::new(perm);

    // Create a dummy proof where sum of log_arities is huge
    let proof = FriProof {
        commit_phase_commits: vec![Default::default(); 10],
        commit_pow_witnesses: vec![Val::ZERO; 10],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 10,
                sibling_values: vec![Challenge::ZERO; (1 << 10) - 1],
                opening_proof: Default::default(),
            }; 10],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    // total_log_reduction = 10 * 10 = 100.
    // log_global_max_height = 100 + 1 + 0 = 101.
    // This should pass all initial checks but might panic when sampling 101 bits if field is smaller,
    // or when creating domain if log_global_max_height > Val::TWO_ADICITY.
    let domain = <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, 1 << 4);
    let commitments_with_opening_points = vec![(
        Default::default(),
        vec![(domain, vec![(Challenge::ZERO, vec![Challenge::ZERO])])],
    )];

    let result = pcs.verify(commitments_with_opening_points, &proof, &mut challenger);
    println!("Result: {:?}", result);
}
