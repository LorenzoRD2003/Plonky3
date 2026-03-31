
use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing};
use p3_fri::{FriProof, FriParameters, QueryProof, CommitPhaseProofStep, CommitmentWithOpeningPoints};
use p3_fri::verifier::{verify_fri};
use p3_challenger::DuplexChallenger;
use p3_commit::{BatchOpening, BatchOpeningRef};
use p3_matrix::{Dimensions, Matrix};
use p3_symmetric::{Permutation, CryptographicPermutation};
use p3_field::coset::TwoAdicMultiplicativeCoset;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;

#[derive(Clone)]
struct TestPermutation;
impl<F: Clone> Permutation<[F; 16]> for TestPermutation {
    fn permute_mut(&self, _input: &mut [F; 16]) {}
}
impl<F: Clone> CryptographicPermutation<[F; 16]> for TestPermutation {}

struct DummyFolding;
impl p3_fri::FriFoldingStrategy<Val, Challenge> for DummyFolding {
    type InputProof = Vec<BatchOpening<Val, DummyMmcs>>;
    type InputError = ();
    fn extra_query_index_bits(&self) -> usize { 0 }
    fn fold_row(&self, _index: usize, _log_height: usize, _log_arity: usize, _beta: Challenge, _evals: impl Iterator<Item = Challenge>) -> Challenge { Challenge::ZERO }
    fn fold_matrix<M: Matrix<Challenge>>(&self, _beta: Challenge, _log_arity: usize, _m: M) -> Vec<Challenge> { vec![] }
}

#[derive(Clone, Debug)]
struct DummyMmcs;

impl p3_commit::Mmcs<Val> for DummyMmcs {
    type Commitment = [Val; 8];
    type ProverData<M> = ();
    type Proof = ();
    type Error = ();
    fn open_batch<M: Matrix<Val>>(&self, _index: usize, _prover_data: &Self::ProverData<M>) -> BatchOpening<Val, Self> {
        BatchOpening {
            opened_values: vec![],
            opening_proof: (),
        }
    }
    fn verify_batch(&self, _commit: &Self::Commitment, _dimensions: &[Dimensions], _index: usize, _proof: BatchOpeningRef<'_, Val, Self>) -> Result<(), Self::Error> { Ok(()) }
    fn commit<M: Matrix<Val>>(&self, _inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) { ([Val::ZERO; 8], ()) }
    fn get_matrices<'a, M: Matrix<Val>>(&self, _prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> { vec![] }
}
impl p3_commit::Mmcs<Challenge> for DummyMmcs {
    type Commitment = [Val; 8];
    type ProverData<M> = ();
    type Proof = ();
    type Error = ();
    fn open_batch<M: Matrix<Challenge>>(&self, _index: usize, _prover_data: &Self::ProverData<M>) -> BatchOpening<Challenge, Self> {
        BatchOpening {
            opened_values: vec![],
            opening_proof: (),
        }
    }
    fn verify_batch(&self, _commit: &Self::Commitment, _dimensions: &[Dimensions], _index: usize, _proof: BatchOpeningRef<'_, Challenge, Self>) -> Result<(), Self::Error> { Ok(()) }
    fn commit<M: Matrix<Challenge>>(&self, _inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) { ([Val::ZERO; 8], ()) }
    fn get_matrices<'a, M: Matrix<Challenge>>(&self, _prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> { vec![] }
}

#[test]
fn test_panic_underflow_fixed() {
    let folding = DummyFolding;
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: DummyMmcs,
    };

    let proof = FriProof {
        commit_phase_commits: vec![],
        commit_pow_witnesses: vec![],
        query_proofs: vec![
            QueryProof {
                input_proof: vec![],
                commit_phase_openings: vec![],
            }
        ],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger: DuplexChallenger<Val, TestPermutation, 16, 8> = DuplexChallenger::new(TestPermutation);

    let commitments_with_opening_points: Vec<CommitmentWithOpeningPoints<Challenge, [Val; 8], TwoAdicMultiplicativeCoset<Val>>> = vec![
        (
            [Val::ZERO; 8],
            vec![
                (TwoAdicMultiplicativeCoset::new(Val::ONE, 2).unwrap(), vec![])
            ],
        )
    ];

    let result = verify_fri::<DummyFolding, Val, Challenge, DummyMmcs, DummyMmcs, _>(
        &folding,
        &params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &DummyMmcs,
    );
    assert!(result.is_err());
}

#[test]
fn test_dos_large_allocation_fixed() {
    let folding = DummyFolding;
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: DummyMmcs,
    };

    let proof = FriProof {
        commit_phase_commits: vec![[Val::ZERO; 8]],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![
            QueryProof {
                input_proof: vec![],
                commit_phase_openings: vec![
                    CommitPhaseProofStep {
                        log_arity: 60, // Large arity
                        sibling_values: vec![Challenge::ZERO; 100],
                        opening_proof: (),
                    }
                ],
            }
        ],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger: DuplexChallenger<Val, TestPermutation, 16, 8> = DuplexChallenger::new(TestPermutation);
    let commitments_with_opening_points = vec![];

    let result = verify_fri::<DummyFolding, Val, Challenge, DummyMmcs, DummyMmcs, _>(
        &folding,
        &params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &DummyMmcs,
    );
    assert!(result.is_err());
}
