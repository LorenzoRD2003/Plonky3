use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{DuplexChallenger, FieldChallenger, CanObserve};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2Dit;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
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

#[test]
fn test_fri_panic_too_few_rounds() {
    let mut rng = SmallRng::seed_from_u64(1);
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
    let evals = RowMajorMatrix::<Val>::rand_nonzero(&mut rng, deg, 1);

    let (commitment, prover_data) =
        <TwoAdicFriPcs<BabyBear, Radix2Dit<BabyBear>, ValMmcs, ChallengeMmcs> as Pcs<
            Challenge,
            Challenger,
        >>::commit(&pcs, vec![(domain, evals)]);

    let mut challenger = Challenger::new(perm.clone());
    challenger.observe(commitment.clone());
    let zeta: Challenge = challenger.sample_algebra_element();
    let (opened_values, mut proof) = pcs.open(vec![(&prover_data, vec![vec![zeta]])], &mut challenger);

    // Mangle the proof to have 0 FRI rounds
    proof.commit_phase_commits = vec![];
    proof.query_proofs.iter_mut().for_each(|qp| qp.commit_phase_openings = vec![]);

    let mut v_challenger = Challenger::new(perm);
    v_challenger.observe(commitment.clone());
    let zeta = v_challenger.sample_algebra_element();

    let commitments_with_opening_points = vec![(
        commitment,
        vec![(domain, vec![(zeta, opened_values[0][0][0].clone())])],
    )];

    // This should NOT panic, but return an error
    let result = pcs.verify(
        commitments_with_opening_points,
        &proof,
        &mut v_challenger,
    );

    match result {
        Ok(_) => panic!("Should have failed"),
        Err(e) => println!("Correctly failed with error: {:?}", e),
    }
}

#[test]
fn test_fri_panic_mismatched_arity_length() {
    let mut rng = SmallRng::seed_from_u64(1);
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
    let evals = RowMajorMatrix::<Val>::rand_nonzero(&mut rng, deg, 1);

    let (commitment, prover_data) =
        <TwoAdicFriPcs<BabyBear, Radix2Dit<BabyBear>, ValMmcs, ChallengeMmcs> as Pcs<
            Challenge,
            Challenger,
        >>::commit(&pcs, vec![(domain, evals)]);

    let mut challenger = Challenger::new(perm.clone());
    challenger.observe(commitment.clone());
    let zeta: Challenge = challenger.sample_algebra_element();
    let (opened_values, mut proof) = pcs.open(vec![(&prover_data, vec![vec![zeta]])], &mut challenger);

    // Mangle the proof to have mismatched sibling_values length
    // Arity is 1 << log_arity. If log_arity is 1, arity is 2. sibling_values should be length 1.
    proof.query_proofs[0].commit_phase_openings[0].sibling_values = vec![];

    let mut v_challenger = Challenger::new(perm);
    v_challenger.observe(commitment.clone());
    let zeta = v_challenger.sample_algebra_element();

    let commitments_with_opening_points = vec![(
        commitment,
        vec![(domain, vec![(zeta, opened_values[0][0][0].clone())])],
    )];

    // This should NOT panic, but return an error
    let result = pcs.verify(
        commitments_with_opening_points,
        &proof,
        &mut v_challenger,
    );

    match result {
        Ok(_) => panic!("Should have failed"),
        Err(e) => println!("Correctly failed with error: {:?}", e),
    }
}
