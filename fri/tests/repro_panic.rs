use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::{BatchOpening, ExtensionMmcs, Pcs};
use p3_dft::Radix2Dit;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{CommitPhaseProofStep, FriParameters, FriProof, QueryProof, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
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
type MyPcs = TwoAdicFriPcs<BabyBear, Radix2Dit<BabyBear>, ValMmcs, ChallengeMmcs>;

fn setup_pcs() -> (MyPcs, Challenger) {
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
    (pcs, Challenger::new(perm))
}

#[test]
fn test_no_panic_large_log_arity_in_query() {
    let (pcs, mut challenger) = setup_pcs();
    let proof: <MyPcs as Pcs<Challenge, Challenger>>::Proof = FriProof {
        commit_phase_commits: vec![Default::default()],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening {
                opened_values: vec![],
                opening_proof: Default::default(),
            }],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 64, // Should be rejected by new checks
                sibling_values: vec![],
                opening_proof: Default::default(),
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let result = pcs.verify(vec![], &proof, &mut challenger);
    assert!(result.is_err());
}

#[test]
fn test_no_panic_large_height() {
    let (pcs, mut challenger) = setup_pcs();
    let proof: <MyPcs as Pcs<Challenge, Challenger>>::Proof = FriProof {
        commit_phase_commits: vec![Default::default(); 28],
        commit_pow_witnesses: vec![Val::ZERO; 28],
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening {
                opened_values: vec![vec![]],
                opening_proof: Default::default(),
            }],
            commit_phase_openings: (0..28)
                .map(|_| CommitPhaseProofStep {
                    log_arity: 1,
                    sibling_values: vec![Challenge::ZERO],
                    opening_proof: Default::default(),
                })
                .collect(),
        }],
        final_poly: vec![Challenge::ZERO; 1],
        query_pow_witness: Val::ZERO,
    };

    use p3_field::coset::TwoAdicMultiplicativeCoset;
    let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 1).unwrap();
    let commitments_with_opening_points = vec![(
        Default::default(),
        vec![(domain, vec![(Challenge::ZERO, vec![Challenge::ZERO])])],
    )];

    let result = pcs.verify(commitments_with_opening_points, &proof, &mut challenger);
    assert!(result.is_err());
}

#[test]
fn test_no_panic_height_mismatch() {
    let (pcs, mut challenger) = setup_pcs();
    let proof: <MyPcs as Pcs<Challenge, Challenger>>::Proof = FriProof {
        commit_phase_commits: vec![Default::default()],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening {
                opened_values: vec![vec![]],
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

    use p3_field::coset::TwoAdicMultiplicativeCoset;
    let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 5).unwrap(); // height 2^5
    let commitments_with_opening_points = vec![(
        Default::default(),
        vec![(domain, vec![(Challenge::ZERO, vec![Challenge::ZERO])])],
    )];

    let result = pcs.verify(commitments_with_opening_points, &proof, &mut challenger);
    assert!(result.is_err());
}
