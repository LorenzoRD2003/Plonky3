use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{DuplexChallenger, FieldChallenger, CanObserve};
use p3_commit::{ExtensionMmcs, Pcs, BatchOpening};
use p3_dft::Radix2Dit;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs, FriProof, QueryProof};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::rngs::SmallRng;
use rand::{SeedableRng};
use std::panic;

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
fn test_verify_fri_underflow_panic() {
    let mut rng = SmallRng::seed_from_u64(0);
    let log_final_poly_len = 0;
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let input_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
    let fri_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));
    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: fri_mmcs,
    };
    let dft = Radix2Dit::default();
    let pcs = MyPcs::new(dft, input_mmcs, fri_params);

    let deg = 1 << 4;
    let domain = <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, deg);
    let evals = RowMajorMatrix::<Val>::rand_nonzero(&mut rng, deg, 1);
    let (commitment, _prover_data) =
        <MyPcs as Pcs<Challenge, Challenger>>::commit(&pcs, vec![(domain, evals)]);

    // Construct a malformed proof with NO commit phase commitments
    // This should make total_log_reduction = 0.
    // log_global_max_height = 0 + 1 + 0 = 1.
    // But input matrix has log_height = 4 + 1 = 5.
    // In open_input, it will try to compute bits_reduced = 1 - 5 which underflows.

    let proof = FriProof {
        commit_phase_commits: vec![],
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening {
                opened_values: vec![vec![Val::ZERO]],
                opening_proof: vec![],
            }],
            commit_phase_openings: vec![],
        }],
        final_poly: vec![Challenge::ZERO; 1],
        commit_pow_witnesses: vec![],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = Challenger::new(perm);
    challenger.observe(commitment.clone());
    let zeta: Challenge = challenger.sample_algebra_element();

    let commitments_with_opening_points = vec![(
        commitment,
        vec![(domain, vec![(zeta, vec![Challenge::ZERO])])],
    )];

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        pcs.verify(commitments_with_opening_points, &proof, &mut challenger)
    }));

    match result {
        Ok(Err(_)) => {} // Expected error
        Ok(Ok(())) => panic!("Should have failed"),
        Err(_) => panic!("Verifier panicked!"),
    }
}
