use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::{ExtensionMmcs, BatchOpening, Mmcs};
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, FriProof, QueryProof, CommitPhaseProofStep, TwoAdicFriFolding};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use core::marker::PhantomData;
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

#[test]
fn test_verify_fri_underflow_rejection() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
    let fri_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));

    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: fri_mmcs.clone(),
    };

    let folding = TwoAdicFriFolding::<Vec<BatchOpening<Val, ValMmcs>>, _>(PhantomData);
    let mut challenger = Challenger::new(perm.clone());

    // Create a dummy proof with 0 log_arities
    let proof = FriProof {
        commit_phase_commits: vec![],
        commit_pow_witnesses: vec![],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![],
        }],
        final_poly: vec![Challenge::ZERO; 1],
        query_pow_witness: Val::ZERO,
    };

    // commitments_with_opening_points has a matrix with height 2^2
    // log_height = 2 + log_blowup(1) = 3
    // But proof has 0 log_arities, so log_global_max_height = 0 + 1 + 0 = 1
    // Previously this would have underflowed in bits_reduced calculation or mismatched.
    let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 2).unwrap();
    let commitments_with_opening_points = vec![(
        val_mmcs.commit_vec(vec![Val::ZERO; 4]).0,
        vec![(domain, vec![(Challenge::ZERO, vec![Challenge::ZERO])])],
    )];

    let result = p3_fri::verifier::verify_fri(
        &folding,
        &params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &val_mmcs,
    );
    assert!(result.is_err());
}

#[test]
fn test_verify_fri_oversized_arity_rejection() {
    let mut rng = SmallRng::seed_from_u64(0);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
    let fri_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));

    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: fri_mmcs.clone(),
    };

    let folding = TwoAdicFriFolding::<Vec<BatchOpening<Val, ValMmcs>>, _>(PhantomData);
    let mut challenger = Challenger::new(perm.clone());

    // Create a proof with a huge log_arity
    let proof = FriProof {
        commit_phase_commits: vec![fri_mmcs.commit_vec(vec![Challenge::ZERO; 2]).0],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 60, // Huge arity
                sibling_values: vec![],
                opening_proof: vec![],
            }],
        }],
        final_poly: vec![Challenge::ZERO; 1],
        query_pow_witness: Val::ZERO,
    };

    let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 2).unwrap();
    let commitments_with_opening_points = vec![(
        val_mmcs.commit_vec(vec![Val::ZERO; 4]).0,
        vec![(domain, vec![(Challenge::ZERO, vec![Challenge::ZERO])])],
    )];

    let result = p3_fri::verifier::verify_fri(
        &folding,
        &params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &val_mmcs,
    );
    assert!(result.is_err());
}
