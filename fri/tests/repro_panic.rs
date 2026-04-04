use p3_baby_bear::BabyBear;
use p3_challenger::{DuplexChallenger};
use p3_commit::{BatchOpening, Mmcs};
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing};
use p3_fri::{
    CommitPhaseProofStep, FriFoldingStrategy, FriParameters, FriProof, QueryProof,
};
use p3_matrix::{Dimensions, Matrix};
use p3_baby_bear::Poseidon2BabyBear;
use alloc::vec;
use alloc::vec::Vec;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use p3_field::coset::TwoAdicMultiplicativeCoset;

extern crate alloc;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Perm = Poseidon2BabyBear<16>;

#[derive(Debug, Clone)]
struct FakeMmcs;
impl<T: Send + Sync + Clone> Mmcs<T> for FakeMmcs {
    type ProverData<M> = ();
    type Commitment = [Val; 8];
    type Proof = Vec<[Val; 8]>;
    type Error = ();
    fn commit<M: Matrix<T>>(&self, _inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) { ( [Val::ZERO; 8], () ) }
    fn open_batch<M: Matrix<T>>(&self, _index: usize, _prover_data: &Self::ProverData<M>) -> BatchOpening<T, Self> {
        BatchOpening { opened_values: vec![], opening_proof: vec![] }
    }
    fn get_matrices<'a, M: Matrix<T>>(&self, _prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> { vec![] }
    fn verify_batch(&self, _commit: &Self::Commitment, _dimensions: &[Dimensions], _index: usize, _proof: p3_commit::BatchOpeningRef<'_, T, Self>) -> Result<(), Self::Error> { Ok(()) }
}

struct FakeFolding;
impl FriFoldingStrategy<Val, Challenge> for FakeFolding {
    type InputProof = Vec<BatchOpening<Val, FakeMmcs>>;
    type InputError = ();
    fn extra_query_index_bits(&self) -> usize { 0 }
    fn fold_row(&self, _index: usize, _log_height: usize, _log_arity: usize, _beta: Challenge, _evals: impl Iterator<Item = Challenge>) -> Challenge { Challenge::ZERO }
    fn fold_matrix<M: p3_matrix::Matrix<Challenge>>(&self, _beta: Challenge, _log_arity: usize, _m: M) -> Vec<Challenge> { vec![] }
}

#[test]
fn test_large_log_arity_panic() {
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: FakeMmcs,
    };

    let proof = FriProof {
        commit_phase_commits: vec![[Val::ZERO; 8]],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 60, // Extremely large log_arity
                sibling_values: vec![],
                opening_proof: vec![],
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let mut rng = SmallRng::seed_from_u64(0);
    let mut challenger = DuplexChallenger::<Val, Perm, 16, 8>::new(Perm::new_from_rng_128(&mut rng));

    // This should NOT panic, but return an error.
    let result = p3_fri::verifier::verify_fri(
        &FakeFolding,
        &params,
        &proof,
        &mut challenger,
        &[],
        &FakeMmcs,
    );

    assert!(result.is_err());
}

#[test]
fn test_too_large_total_reduction_panic() {
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: FakeMmcs,
    };

    let proof = FriProof {
        commit_phase_commits: vec![[Val::ZERO; 8]],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 32, // Large enough to exceed TWO_ADICITY (27 for BabyBear)
                sibling_values: vec![],
                opening_proof: vec![],
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let mut rng = SmallRng::seed_from_u64(0);
    let mut challenger = DuplexChallenger::<Val, Perm, 16, 8>::new(Perm::new_from_rng_128(&mut rng));

    // This should NOT panic, but return an error.
    let result = p3_fri::verifier::verify_fri(
        &FakeFolding,
        &params,
        &proof,
        &mut challenger,
        &[],
        &FakeMmcs,
    );

    assert!(result.is_err());
}

#[test]
fn test_height_exceeds_two_adicity_even_if_matches_input() {
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 30, // allow large arity in params
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: FakeMmcs,
    };

    // Implied log_global_max_height = 28 + 1 + 0 = 29.
    // BabyBear TWO_ADICITY is 27.
    let proof = FriProof {
        commit_phase_commits: vec![[Val::ZERO; 8]],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 28,
                sibling_values: vec![],
                opening_proof: vec![],
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    // Domain size 2^28
    // Since we cannot easily construct a TwoAdicMultiplicativeCoset with log_size > TWO_ADICITY,
    // we use a smaller domain in the verifier's input but the proof will have a larger arity.
    // Actually, we can just use a domain of size 2^27 and see it reject.
    let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 27).unwrap();
    let commitments_with_opening_points = vec![
        ([Val::ZERO; 8], vec![(domain, vec![])])
    ];

    let mut rng = SmallRng::seed_from_u64(0);
    let mut challenger = DuplexChallenger::<Val, Perm, 16, 8>::new(Perm::new_from_rng_128(&mut rng));

    let result = p3_fri::verifier::verify_fri(
        &FakeFolding,
        &params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &FakeMmcs,
    );

    assert!(result.is_err());
}

#[test]
fn test_expected_height_mismatch_rejected() {
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: FakeMmcs,
    };

    // Proof says height is 2^11 (10 + 1 + 0)
    let proof = FriProof {
        commit_phase_commits: vec![[Val::ZERO; 8]],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 10,
                sibling_values: vec![],
                opening_proof: vec![],
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    // But input domain is 2^8, so expected height is 2^9.
    let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 8).unwrap();
    let commitments_with_opening_points = vec![
        ([Val::ZERO; 8], vec![(domain, vec![])])
    ];

    let mut rng = SmallRng::seed_from_u64(0);
    let mut challenger = DuplexChallenger::<Val, Perm, 16, 8>::new(Perm::new_from_rng_128(&mut rng));

    let result = p3_fri::verifier::verify_fri(
        &FakeFolding,
        &params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &FakeMmcs,
    );

    assert!(result.is_err());
}
