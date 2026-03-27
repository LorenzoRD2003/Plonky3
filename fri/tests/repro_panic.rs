use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::{ExtensionMmcs, Pcs};
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{
    CommitPhaseProofStep, FriParameters, FriProof, QueryProof, TwoAdicFriPcs,
};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation, MerkleCap};
use p3_baby_bear::Poseidon2BabyBear;
use p3_dft::Radix2Dit;
use rand::{SeedableRng};
use rand::rngs::SmallRng;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<Val, Val, MyHash, MyCompress, 2, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type MyPcs = TwoAdicFriPcs<BabyBear, Radix2Dit<BabyBear>, ValMmcs, ChallengeMmcs>;

#[test]
fn test_repro_panic_large_log_arity() {
    let mut rng = SmallRng::seed_from_u64(42);
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
    let dft = Radix2Dit::default();
    let pcs = MyPcs::new(dft, val_mmcs, fri_params.clone());

    // Create a dummy proof with a very large log_arity
    let proof = FriProof {
        commit_phase_commits: vec![MerkleCap::new(vec![[Val::ZERO; 8]])],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 100,
                sibling_values: vec![],
                opening_proof: vec![],
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = Challenger::new(perm);
    let commitments_with_opening_points = vec![];
    let result = pcs.verify(commitments_with_opening_points, &proof, &mut challenger);
    assert!(result.is_err());
}

#[test]
fn test_repro_panic_large_total_reduction() {
    let mut rng = SmallRng::seed_from_u64(42);
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
    let dft = Radix2Dit::default();
    let pcs = MyPcs::new(dft, val_mmcs, fri_params.clone());

    // log_arity sum = 60 + 10 = 70 > 64
    let proof = FriProof {
        commit_phase_commits: vec![
            MerkleCap::new(vec![[Val::ZERO; 8]]),
            MerkleCap::new(vec![[Val::ZERO; 8]]),
        ],
        commit_pow_witnesses: vec![Val::ZERO, Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![
                CommitPhaseProofStep {
                    log_arity: 60,
                    sibling_values: vec![Challenge::ZERO; 0],
                    opening_proof: vec![],
                },
                CommitPhaseProofStep {
                    log_arity: 10,
                    sibling_values: vec![Challenge::ZERO; 0],
                    opening_proof: vec![],
                },
            ],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = Challenger::new(perm);
    let commitments_with_opening_points = vec![];
    let result = pcs.verify(commitments_with_opening_points, &proof, &mut challenger);
    assert!(result.is_err());
}

#[test]
fn test_repro_panic_height_mismatch_underflow() {
    let mut rng = SmallRng::seed_from_u64(42);
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
    let dft = Radix2Dit::default();
    let pcs = MyPcs::new(dft, val_mmcs, fri_params.clone());

    // Prover claims total_log_reduction = 1, so log_global_max_height = 1 + 1 + 0 = 2.
    // But verifier expects log_height = log2(8) + 1 = 4.
    let proof = FriProof {
        commit_phase_commits: vec![MerkleCap::new(vec![[Val::ZERO; 8]])],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![
                p3_commit::BatchOpening::new(vec![vec![Val::ZERO]], vec![])
            ],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 1,
                sibling_values: vec![Challenge::ZERO; 1],
                opening_proof: vec![],
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = Challenger::new(perm);

    use p3_field::coset::TwoAdicMultiplicativeCoset;
    let commitments_with_opening_points = vec![(
        MerkleCap::new(vec![[Val::ZERO; 8]]),
        vec![(
            TwoAdicMultiplicativeCoset::new(Val::ONE, 3).unwrap(), // log_height = 3 + 1 = 4
            vec![(Challenge::ZERO, vec![Challenge::ZERO])],
        )]
    )];

    let result = pcs.verify(commitments_with_opening_points, &proof, &mut challenger);
    assert!(result.is_err());
}
