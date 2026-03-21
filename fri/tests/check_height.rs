use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{DuplexChallenger, FieldChallenger};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2Dit;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_field::Field;
use rand::SeedableRng;
use rand::rngs::SmallRng;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type MyPcs = TwoAdicFriPcs<BabyBear, Radix2Dit<BabyBear>, ValMmcs, ChallengeMmcs>;

#[test]
fn test_valid_proof_verification_with_blowup_2() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let input_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
    let fri_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));
    let fri_params = FriParameters {
        log_blowup: 2, // blowup 2
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 10,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: fri_mmcs,
    };
    let dft = Radix2Dit::default();
    let pcs = MyPcs::new(dft, input_mmcs, fri_params);

    let log_n = 10;
    let d = <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, 1 << log_n);
    let evals = RowMajorMatrix::rand(&mut rng, 1 << log_n, 1);

    let (comm, data) = <MyPcs as Pcs<Challenge, Challenger>>::commit(&pcs, [(d, evals)]);

    let mut challenger = Challenger::new(perm.clone());
    let zeta: Challenge = challenger.sample_algebra_element();
    let (values, proof) = pcs.open(vec![(&data, vec![vec![zeta]])], &mut challenger);

    let mut challenger = Challenger::new(perm);
    let _zeta: Challenge = challenger.sample_algebra_element();

    let commitments_with_opening_points = vec![(
        comm,
        vec![(d, vec![(zeta, values[0][0][0].clone())])],
    )];

    pcs.verify(commitments_with_opening_points, &proof, &mut challenger).expect("Verification failed!");
}
