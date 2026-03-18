use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{DuplexChallenger};
use p3_commit::{ExtensionMmcs};
use p3_dft::Radix2Dit;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_uni_stark::{StarkConfig, Proof, Commitments, OpenedValues, verify};
use p3_fri::{FriParameters, TwoAdicFriPcs, FriProof};
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
type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

use p3_air::{Air, AirBuilder, BaseAir};

struct DummyAir;
impl<F> BaseAir<F> for DummyAir {
    fn width(&self) -> usize { 1 }
}
impl<AB: AirBuilder> Air<AB> for DummyAir {
    fn eval(&self, _builder: &mut AB) {}
}

#[test]
fn test_stark_panic_too_large_degree() {
    let mut rng = SmallRng::seed_from_u64(1);
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
    let dft = Radix2Dit::default();
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let config = MyConfig::new(pcs, Challenger::new(perm));

    let proof = Proof {
        commitments: Commitments {
            trace: Default::default(),
            quotient_chunks: Default::default(),
            random: None,
        },
        opened_values: OpenedValues {
            trace_local: vec![Challenge::ZERO],
            trace_next: None,
            preprocessed_local: None,
            preprocessed_next: None,
            quotient_chunks: vec![vec![Challenge::ZERO]],
            random: None,
        },
        opening_proof: FriProof {
            commit_phase_commits: vec![],
            commit_pow_witnesses: vec![],
            query_proofs: vec![],
            final_poly: vec![],
            query_pow_witness: Val::ZERO,
        },
        degree_bits: 100, // Way too large
    };

    let result = verify(&config, &DummyAir, &proof, &[]);
    assert!(result.is_err());
}
