use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{CanObserve, DuplexChallenger, FieldChallenger};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2Dit;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{CommitPhaseProofStep, FriParameters, FriProof, QueryProof, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

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
fn test_verifier_underflow_panic() {
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

    let log_degree = 4;
    let deg = 1 << log_degree;
    let domain = <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, deg);
    let evaluations = vec![(
        domain,
        RowMajorMatrix::<Val>::rand_nonzero(&mut rng, deg, 1),
    )];

    let (commitment, prover_data) =
        <MyPcs as Pcs<Challenge, Challenger>>::commit(&pcs, evaluations);

    let zeta: Challenge = Challenge::ZERO;
    let (opened_values, proof) = pcs.open(
        vec![(&prover_data, vec![vec![zeta]])],
        &mut Challenger::new(perm.clone()),
    );

    // Malicious proof: empty commit_phase_commits and query_proofs with no openings
    // This will result in log_global_max_height = 0 + log_blowup + log_final_poly_len = 1 + 0 = 1.
    // But expected log_global_max_height is log_degree + log_blowup = 4 + 1 = 5.
    let malicious_proof = FriProof {
        commit_phase_commits: vec![],
        commit_pow_witnesses: vec![],
        query_proofs: vec![QueryProof {
            input_proof: proof.query_proofs[0].input_proof.clone(),
            commit_phase_openings: vec![],
        }],
        final_poly: vec![Challenge::ZERO; 1],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = Challenger::new(perm);
    let commitments_with_opening_points = vec![(
        commitment,
        vec![(domain, vec![(zeta, opened_values[0][0][0].clone())])],
    )];

    // This should not panic
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pcs.verify(
            commitments_with_opening_points,
            &malicious_proof,
            &mut challenger,
        )
    }));

    match result {
        Ok(Err(_)) => println!("Correctly returned error"),
        Ok(Ok(())) => println!("Incorrectly verified proof"),
        Err(_) => panic!("Verifier panicked!"),
    }
}
