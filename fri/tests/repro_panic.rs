extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{
    CommitPhaseProofStep, CommitmentWithOpeningPoints, FriFoldingStrategy, FriParameters, FriProof,
    QueryProof,
};
use p3_fri::verifier::verify_fri;
use p3_matrix::Dimensions;
use p3_matrix::Matrix;
use rand::rngs::SmallRng;
use rand::SeedableRng;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Perm = Poseidon2BabyBear<16>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

#[derive(Clone)]
struct MockMmcs;

impl<T: Clone + Send + Sync> Mmcs<T> for MockMmcs {
    type Commitment = [Val; 8];
    type Proof = Vec<Val>;
    type Error = ();
    type ProverData<M> = ();

    fn open_batch<M: Matrix<T>>(&self, _index: usize, _prover_data: &Self::ProverData<M>) -> BatchOpening<T, Self> {
        BatchOpening {
            opened_values: vec![vec![]],
            opening_proof: vec![],
        }
    }

    fn verify_batch(
        &self,
        _commitment: &Self::Commitment,
        _dimensions: &[Dimensions],
        _index: usize,
        _proof: BatchOpeningRef<'_, T, Self>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn commit<M: Matrix<T>>(&self, _matrices: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        ([Val::ZERO; 8], ())
    }

    fn get_matrices<'a, M: Matrix<T>>(&self, _prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        vec![]
    }
}

struct MockFolding;

impl FriFoldingStrategy<Val, Challenge> for MockFolding {
    type InputProof = Vec<BatchOpening<Val, MockMmcs>>;
    type InputError = ();

    fn extra_query_index_bits(&self) -> usize {
        0
    }

    fn fold_row(
        &self,
        _index: usize,
        _log_height: usize,
        _log_arity: usize,
        _beta: Challenge,
        _evals: impl Iterator<Item = Challenge>,
    ) -> Challenge {
        Challenge::ZERO
    }

    fn fold_matrix<M: Matrix<Challenge>>(&self, _beta: Challenge, _log_arity: usize, _m: M) -> Vec<Challenge> {
        vec![]
    }
}

#[test]
fn test_panic_large_arity() {
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: MockMmcs,
    };

    let proof: FriProof<Challenge, MockMmcs, Val, Vec<BatchOpening<Val, MockMmcs>>> = FriProof {
        commit_phase_commits: vec![[Val::ZERO; 8]],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 63, // Extremely large arity
                sibling_values: vec![Challenge::ZERO; 0],
                opening_proof: vec![],
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = Challenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(0)));
    let commitments_with_opening_points = vec![];

    let result = verify_fri::<MockFolding, Val, Challenge, MockMmcs, MockMmcs, Challenger>(
        &MockFolding,
        &params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &MockMmcs,
    );
    assert!(result.is_err());
}

#[test]
fn test_panic_height_mismatch() {
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: MockMmcs,
    };

    let proof: FriProof<Challenge, MockMmcs, Val, Vec<BatchOpening<Val, MockMmcs>>> = FriProof {
        commit_phase_commits: vec![[Val::ZERO; 8]],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening {
                opened_values: vec![vec![]],
                opening_proof: vec![],
            }],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 1,
                sibling_values: vec![Challenge::ZERO; 1],
                opening_proof: vec![],
            }],
        }],
        final_poly: vec![Challenge::ZERO; 1],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = Challenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(0)));

    let commitments_with_opening_points: Vec<CommitmentWithOpeningPoints<Challenge, [Val; 8], TwoAdicMultiplicativeCoset<Val>>> = vec![
        (
            [Val::ZERO; 8],
            vec![
                (TwoAdicMultiplicativeCoset::new(Val::ONE, 3).unwrap(), vec![(Challenge::ZERO, vec![Challenge::ZERO])])
            ],
        )
    ];

    let result = verify_fri::<MockFolding, Val, Challenge, MockMmcs, MockMmcs, Challenger>(
        &MockFolding,
        &params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &MockMmcs,
    );
    assert!(result.is_err());
}

#[test]
fn test_panic_exceed_two_adicity() {
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 30,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: MockMmcs,
    };

    let proof: FriProof<Challenge, MockMmcs, Val, Vec<BatchOpening<Val, MockMmcs>>> = FriProof {
        commit_phase_commits: vec![[Val::ZERO; 8]; 30],
        commit_pow_witnesses: vec![Val::ZERO; 30],
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening {
                opened_values: vec![vec![]],
                opening_proof: vec![],
            }],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 1,
                sibling_values: vec![Challenge::ZERO; 1],
                opening_proof: vec![],
            }; 30],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = Challenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(0)));

    let commitments_with_opening_points: Vec<CommitmentWithOpeningPoints<Challenge, [Val; 8], TwoAdicMultiplicativeCoset<Val>>> = vec![
        (
            [Val::ZERO; 8],
            vec![
                (TwoAdicMultiplicativeCoset::new(Val::ONE, 26).unwrap(), vec![(Challenge::ZERO, vec![Challenge::ZERO])])
            ],
        )
    ];

    let result = verify_fri::<MockFolding, Val, Challenge, MockMmcs, MockMmcs, Challenger>(
        &MockFolding,
        &params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &MockMmcs,
    );
    assert!(result.is_err());
}

#[test]
fn test_panic_zero_arity() {
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: MockMmcs,
    };

    let proof: FriProof<Challenge, MockMmcs, Val, Vec<BatchOpening<Val, MockMmcs>>> = FriProof {
        commit_phase_commits: vec![[Val::ZERO; 8]],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 0,
                sibling_values: vec![],
                opening_proof: vec![],
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = Challenger::new(Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(0)));
    let commitments_with_opening_points = vec![];

    let result = verify_fri::<MockFolding, Val, Challenge, MockMmcs, MockMmcs, Challenger>(
        &MockFolding,
        &params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &MockMmcs,
    );
    assert!(result.is_err());
}
