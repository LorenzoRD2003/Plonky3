use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{
    CommitPhaseProofStep, FriFoldingStrategy, FriParameters, FriProof,
    QueryProof,
};
use p3_matrix::Dimensions;
use serde::{Deserialize, Serialize};
use thiserror::Error;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DummyMmcs;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DummyProof;

impl Mmcs<Val> for DummyMmcs {
    type Commitment = [Val; 8];
    type Proof = DummyProof;
    type Error = DummyError;
    type ProverData<M> = ();

    fn open_batch<M: p3_matrix::Matrix<Val>>(
        &self,
        _index: usize,
        _prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<Val, Self> {
        unimplemented!()
    }

    fn verify_batch(
        &self,
        _commit: &Self::Commitment,
        _dimensions: &[Dimensions],
        _index: usize,
        _proof: BatchOpeningRef<'_, Val, Self>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn commit<M: p3_matrix::Matrix<Val>>(&self, _matrices: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        unimplemented!()
    }

    fn get_matrices<'a, M: p3_matrix::Matrix<Val>>(&self, _data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        unimplemented!()
    }
}

impl Mmcs<Challenge> for DummyMmcs {
    type Commitment = [Val; 8];
    type Proof = DummyProof;
    type Error = DummyError;
    type ProverData<M> = ();

    fn open_batch<M: p3_matrix::Matrix<Challenge>>(
        &self,
        _index: usize,
        _prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<Challenge, Self> {
        unimplemented!()
    }

    fn verify_batch(
        &self,
        _commit: &Self::Commitment,
        _dimensions: &[Dimensions],
        _index: usize,
        _proof: BatchOpeningRef<'_, Challenge, Self>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn commit<M: p3_matrix::Matrix<Challenge>>(&self, _matrices: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        unimplemented!()
    }

    fn get_matrices<'a, M: p3_matrix::Matrix<Challenge>>(&self, _data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        unimplemented!()
    }
}

#[derive(Debug, Error, Serialize, Deserialize)]
pub enum DummyError {
    #[error("dummy error")]
    Dummy,
}

struct DummyFolding;
impl FriFoldingStrategy<Val, Challenge> for DummyFolding {
    type InputProof = Vec<BatchOpening<Val, DummyMmcs>>;
    type InputError = DummyError;

    fn extra_query_index_bits(&self) -> usize {
        0
    }
    fn fold_row(
        &self,
        _index: usize,
        _log_height: usize,
        _log_arity: usize,
        _beta: Challenge,
        mut evals: impl Iterator<Item = Challenge>,
    ) -> Challenge {
        evals.next().unwrap()
    }
    fn fold_matrix<M: p3_matrix::Matrix<Challenge>>(
        &self,
        _beta: Challenge,
        _log_arity: usize,
        _m: M,
    ) -> Vec<Challenge> {
        unimplemented!()
    }
}

#[derive(Clone)]
struct DummyChallenger;
impl FieldChallenger<Val> for DummyChallenger {
    fn sample_algebra_element<T: p3_field::BasedVectorSpace<Val>>(&mut self) -> T {
        T::from_basis_coefficients_fn(|_| self.sample())
    }
}
impl CanObserve<Val> for DummyChallenger {
    fn observe(&mut self, _value: Val) {}
}
impl CanObserve<[Val; 8]> for DummyChallenger {
    fn observe(&mut self, _value: [Val; 8]) {}
}
impl CanObserve<Challenge> for DummyChallenger {
    fn observe(&mut self, _value: Challenge) {}
}
impl CanSampleBits<usize> for DummyChallenger {
    fn sample_bits(&mut self, _bits: usize) -> usize {
        0
    }
}
impl CanSample<Val> for DummyChallenger {
    fn sample(&mut self) -> Val {
        Val::ZERO
    }
}
impl GrindingChallenger for DummyChallenger {
    type Witness = Val;
    fn check_witness(&mut self, _bits: usize, _witness: Self::Witness) -> bool {
        true
    }
    fn grind(&mut self, _bits: usize) -> Self::Witness {
        Val::ZERO
    }
}

#[test]
fn test_large_arity_rejection() {
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: DummyMmcs,
    };

    let mut challenger = DummyChallenger;

    // A large log_arity that would cause OOM if not validated.
    let malicious_log_arity = 60;

    let proof = FriProof {
        commit_phase_commits: vec![[Val::ZERO; 8]],
        commit_pow_witnesses: vec![Val::ZERO],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: malicious_log_arity,
                sibling_values: vec![],
                opening_proof: DummyProof,
            }],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let result = p3_fri::verifier::verify_fri::<DummyFolding, Val, Challenge, DummyMmcs, DummyMmcs, _>(
        &DummyFolding,
        &params,
        &proof,
        &mut challenger,
        &[],
        &DummyMmcs,
    );

    assert!(result.is_err());
}

#[test]
fn test_large_total_reduction_rejection() {
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: DummyMmcs,
    };

    let mut challenger = DummyChallenger;

    // Sum of log_arities is 62, plus log_blowup=1, plus log_final_poly_len=0 is 63.
    // This is >= usize::BITS (64) if it was 64, but let's go for something that definitely exceeds Val::TWO_ADICITY (which is 27 for BabyBear).
    let proof = FriProof {
        commit_phase_commits: vec![[Val::ZERO; 8]; 30],
        commit_pow_witnesses: vec![Val::ZERO; 30],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 1,
                sibling_values: vec![Challenge::ZERO],
                opening_proof: DummyProof,
            }; 30],
        }],
        final_poly: vec![Challenge::ZERO],
        query_pow_witness: Val::ZERO,
    };

    let result = p3_fri::verifier::verify_fri::<DummyFolding, Val, Challenge, DummyMmcs, DummyMmcs, _>(
        &DummyFolding,
        &params,
        &proof,
        &mut challenger,
        &[],
        &DummyMmcs,
    );

    assert!(result.is_err());
}
