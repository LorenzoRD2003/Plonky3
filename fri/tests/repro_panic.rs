use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::{BatchOpening, Mmcs, BatchOpeningRef};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{
    CommitPhaseProofStep, FriParameters, FriProof, QueryProof,
    TwoAdicFriFolding,
};
use p3_keccak::Keccak256Hash;
use p3_matrix::Dimensions;
use std::marker::PhantomData;
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
struct DummyMmcs<C>(PhantomData<C>);
impl<T: Send + Sync + Clone + Default + Serialize + for<'de> Deserialize<'de>, C: Clone + Serialize + for<'de> Deserialize<'de>> Mmcs<T> for DummyMmcs<C> {
    type ProverData<M> = ();
    type Commitment = C;
    type Proof = ();
    type Error = ();

    fn commit<M: p3_matrix::Matrix<T>>(&self, _inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        unimplemented!()
    }

    fn open_batch<M: p3_matrix::Matrix<T>>(&self, _index: usize, _prover_data: &Self::ProverData<M>) -> BatchOpening<T, Self> {
        unimplemented!()
    }

    fn get_matrices<'a, M: p3_matrix::Matrix<T>>(&self, _prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        unimplemented!()
    }

    fn verify_batch(
        &self,
        _commit: &Self::Commitment,
        _dimensions: &[Dimensions],
        _index: usize,
        _batch_opening: BatchOpeningRef<'_, T, Self>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn test_fri_verifier_rejects_large_log_arity() {
    type Val = BabyBear; // TWO_ADICITY = 27
    type Challenge = BinomialExtensionField<Val, 4>;
    let mmcs = DummyMmcs::<Val>(PhantomData);

    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: mmcs.clone(),
    };

    let proof = FriProof {
        commit_phase_commits: vec![Val::ZERO; 1],
        commit_pow_witnesses: vec![Val::ZERO; 1],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 30, // 30 > 27
                sibling_values: vec![], // sibling_values will be checked against arity - 1, which will fail if empty
                opening_proof: (),
            }],
        }],
        final_poly: vec![Challenge::ZERO; 1],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = SerializingChallenger32::<Val, HashChallenger<u8, Keccak256Hash, 32>>::from_hasher(
        vec![],
        Keccak256Hash {},
    );

    let folding: TwoAdicFriFolding<Vec<BatchOpening<Val, DummyMmcs<Val>>>, ()> = TwoAdicFriFolding(PhantomData);

    let commitments_with_opening_points: Vec<p3_fri::CommitmentWithOpeningPoints<Challenge, Val, TwoAdicMultiplicativeCoset<Val>>> = vec![];

    let result = p3_fri::verifier::verify_fri(
        &folding,
        &params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &DummyMmcs(PhantomData),
    );
    assert!(result.is_err());
}

#[test]
fn test_fri_verifier_rejects_height_mismatch() {
    type Val = BabyBear;
    type Challenge = BinomialExtensionField<Val, 4>;
    let mmcs = DummyMmcs::<Val>(PhantomData);

    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: mmcs.clone(),
    };

    let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 10 - 1).unwrap(); // log_height = 10
    let commitments_with_opening_points = vec![
        (
            Val::ZERO,
            vec![(domain, vec![])]
        )
    ];

    let proof = FriProof {
        commit_phase_commits: vec![Val::ZERO; 1],
        commit_pow_witnesses: vec![Val::ZERO; 1],
        query_proofs: vec![QueryProof {
            input_proof: vec![BatchOpening { opened_values: vec![], opening_proof: () }],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 1,
                sibling_values: vec![Challenge::ZERO; 1],
                opening_proof: (),
            }],
        }],
        final_poly: vec![Challenge::ZERO; 1],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = SerializingChallenger32::<Val, HashChallenger<u8, Keccak256Hash, 32>>::from_hasher(
        vec![],
        Keccak256Hash {},
    );

    let folding: TwoAdicFriFolding<Vec<BatchOpening<Val, DummyMmcs<Val>>>, ()> = TwoAdicFriFolding(PhantomData);

    let result = p3_fri::verifier::verify_fri(
        &folding,
        &params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &DummyMmcs(PhantomData),
    );
    assert!(result.is_err());
}

#[test]
fn test_fri_verifier_rejects_zero_log_arity() {
    type Val = BabyBear;
    type Challenge = BinomialExtensionField<Val, 4>;
    let mmcs = DummyMmcs::<Val>(PhantomData);

    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: mmcs.clone(),
    };

    let proof = FriProof {
        commit_phase_commits: vec![Val::ZERO; 1],
        commit_pow_witnesses: vec![Val::ZERO; 1],
        query_proofs: vec![QueryProof {
            input_proof: vec![],
            commit_phase_openings: vec![CommitPhaseProofStep {
                log_arity: 0, // log_arity = 0 is invalid
                sibling_values: vec![],
                opening_proof: (),
            }],
        }],
        final_poly: vec![Challenge::ZERO; 1],
        query_pow_witness: Val::ZERO,
    };

    let mut challenger = SerializingChallenger32::<Val, HashChallenger<u8, Keccak256Hash, 32>>::from_hasher(
        vec![],
        Keccak256Hash {},
    );

    let folding: TwoAdicFriFolding<Vec<BatchOpening<Val, DummyMmcs<Val>>>, ()> = TwoAdicFriFolding(PhantomData);

    let commitments_with_opening_points: Vec<p3_fri::CommitmentWithOpeningPoints<Challenge, Val, TwoAdicMultiplicativeCoset<Val>>> = vec![];

    let result = p3_fri::verifier::verify_fri(
        &folding,
        &params,
        &proof,
        &mut challenger,
        &commitments_with_opening_points,
        &DummyMmcs(PhantomData),
    );
    assert!(result.is_err());
}
