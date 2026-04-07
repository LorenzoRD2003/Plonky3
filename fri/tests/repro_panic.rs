#![no_std]
extern crate alloc;
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::{BatchOpening, Mmcs, BatchOpeningRef};
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{FriParameters, FriProof, QueryProof, CommitPhaseProofStep, FriFoldingStrategy};
use p3_fri::verifier::{verify_fri, FriError};
use p3_matrix::Dimensions;
use p3_symmetric::CryptographicPermutation;
use alloc::vec::Vec;
use alloc::vec;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;

#[derive(Clone, Debug)]
struct TestPermutation;
impl p3_symmetric::Permutation<[Val; 16]> for TestPermutation {
    fn permute_mut(&self, _input: &mut [Val; 16]) {}
}
impl CryptographicPermutation<[Val; 16]> for TestPermutation {}

type Challenger = DuplexChallenger<Val, TestPermutation, 16, 8>;

#[derive(Clone, Debug)]
struct DummyMmcs;
impl<T: Clone + Send + Sync> Mmcs<T> for DummyMmcs {
    type ProverData<M> = ();
    type Commitment = [Val; 8];
    type Proof = ();
    type Error = ();

    fn open_batch<M: p3_matrix::Matrix<T>>(&self, _index: usize, _prover_data: &Self::ProverData<M>) -> BatchOpening<T, Self> {
        BatchOpening::new(vec![], ())
    }

    fn verify_batch(&self, _commitment: &Self::Commitment, _dimensions: &[Dimensions], _index: usize, _proof: BatchOpeningRef<'_, T, Self>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn commit<M: p3_matrix::Matrix<T>>(&self, _matrices: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        ([Val::ZERO; 8], ())
    }

    fn get_matrices<'a, M: p3_matrix::Matrix<T>>(&self, _prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        vec![]
    }

    fn get_max_height<M: p3_matrix::Matrix<T>>(&self, _prover_data: &Self::ProverData<M>) -> usize {
        1
    }
}

struct DummyFolding;
impl FriFoldingStrategy<Val, Challenge> for DummyFolding {
    type InputProof = Vec<BatchOpening<Val, DummyMmcs>>;
    type InputError = ();

    fn extra_query_index_bits(&self) -> usize { 0 }
    fn fold_row(&self, _index: usize, _log_height: usize, _log_arity: usize, _beta: Challenge, _evals: impl Iterator<Item = Challenge>) -> Challenge { Challenge::ZERO }
    fn fold_matrix<M: p3_matrix::Matrix<Challenge>>(&self, _beta: Challenge, _log_arity: usize, _m: M) -> Vec<Challenge> { vec![] }
}

#[test]
fn test_panic_log_global_max_height_large() {
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: DummyMmcs,
    };

    let mut challenger = Challenger::new(TestPermutation);

    let num_rounds = 100;
    let commit_phase_commits = vec![[Val::ZERO; 8]; num_rounds];
    let commit_pow_witnesses = vec![Val::ZERO; num_rounds];
    let commit_phase_openings = (0..num_rounds).map(|_| CommitPhaseProofStep {
        log_arity: 1,
        sibling_values: vec![Challenge::ZERO],
        opening_proof: (),
    }).collect();

    let proof = FriProof {
        commit_phase_commits,
        commit_pow_witnesses,
        final_poly: vec![Challenge::ZERO; 1],
        query_pow_witness: Val::ZERO,
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings,
        }],
    };

    let result = verify_fri::<DummyFolding, Val, Challenge, DummyMmcs, DummyMmcs, Challenger>(
        &DummyFolding,
        &params,
        &proof,
        &mut challenger,
        &[],
        &DummyMmcs,
    );

    match result {
        Err(FriError::InvalidProofShape) => (),
        _ => panic!("Expected InvalidProofShape error, got {:?}", result),
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
        mmcs: DummyMmcs,
    };

    let mut challenger = Challenger::new(TestPermutation);

    let proof = FriProof {
        commit_phase_commits: vec![[Val::ZERO; 8]],
        commit_pow_witnesses: vec![Val::ZERO],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 100,
                sibling_values: vec![],
                opening_proof: (),
            }],
        }],
    };

    let result = verify_fri::<DummyFolding, Val, Challenge, DummyMmcs, DummyMmcs, Challenger>(
        &DummyFolding,
        &params,
        &proof,
        &mut challenger,
        &[],
        &DummyMmcs,
    );

    match result {
        Err(FriError::InvalidProofShape) => (),
        _ => panic!("Expected InvalidProofShape error, got {:?}", result),
    }
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
        mmcs: DummyMmcs,
    };

    let mut challenger = Challenger::new(TestPermutation);

    let proof = FriProof {
        commit_phase_commits: vec![[Val::ZERO; 8]],
        commit_pow_witnesses: vec![Val::ZERO],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 0,
                sibling_values: vec![],
                opening_proof: (),
            }],
        }],
    };

    let result = verify_fri::<DummyFolding, Val, Challenge, DummyMmcs, DummyMmcs, Challenger>(
        &DummyFolding,
        &params,
        &proof,
        &mut challenger,
        &[],
        &DummyMmcs,
    );

    match result {
        Err(FriError::InvalidProofShape) => (),
        _ => panic!("Expected InvalidProofShape error, got {:?}", result),
    }
}
