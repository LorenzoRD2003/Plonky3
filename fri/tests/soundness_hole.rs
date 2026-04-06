use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{CanObserve, DuplexChallenger, FieldChallenger};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2Dit;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::rngs::SmallRng;
use rand::SeedableRng;

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
fn test_fri_height_mismatch_rejection() {
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

    // Create a matrix of height 2^5
    let deg_bits = 5;
    let deg = 1 << deg_bits;
    let domain = <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, deg);
    let evaluations = RowMajorMatrix::<Val>::rand(&mut rng, deg, 16);

    let (commitment, prover_data) =
        <MyPcs as Pcs<Challenge, Challenger>>::commit(&pcs, vec![(domain, evaluations)]);

    // Generate a valid proof first to get some structures
    let mut p_challenger = Challenger::new(perm.clone());
    p_challenger.observe(&commitment);
    let zeta: Challenge = p_challenger.sample_algebra_element();
    let open_data = vec![(&prover_data, vec![vec![zeta]])];
    let (opened_values, opening_proof) = pcs.open(open_data, &mut p_challenger);

    // Maliciously modify the proof's arity schedule to make log_global_max_height smaller.
    // Expected log_global_max_height = 5 (trace) + 1 (blowup) = 6.
    // proof.query_proofs[0].commit_phase_openings.len() should be 5 rounds if arity 2 each.
    // Let's remove some rounds.
    let mut malicious_proof = opening_proof;

    // Original log_arities: [1, 1, 1, 1, 1, 1]?
    // Wait, total_log_reduction + log_blowup + log_final_poly_len = log_global_max_height
    // log_global_max_height = 6.
    // total_log_reduction = 6 - 1 - 0 = 5.
    // So 5 rounds of arity 2.

    malicious_proof.query_proofs[0].commit_phase_openings.truncate(2); // Now total_log_reduction = 2.
    malicious_proof.commit_phase_commits.truncate(2);
    malicious_proof.commit_pow_witnesses.truncate(2);
    // log_global_max_height will be 2 + 1 + 0 = 3.
    // but log_height of matrix is 5 + 1 = 6.
    // bits_reduced = 3 - 6 -> panic!

    let mut v_challenger = Challenger::new(perm);
    v_challenger.observe(&commitment);
    let zeta: Challenge = v_challenger.sample_algebra_element();

    let commitments_with_opening_points = vec![(
        commitment,
        vec![(domain, vec![(zeta, opened_values[0][0][0].clone())])],
    )];

    let result = pcs.verify(
        commitments_with_opening_points,
        &malicious_proof,
        &mut v_challenger,
    );
    assert!(result.is_err(), "Expected verifier to reject proof with mismatched height");
}
