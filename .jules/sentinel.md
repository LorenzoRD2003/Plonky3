## 2025-05-15 - FRI Verifier DoS and Height Mismatch
**Vulnerability:** The FRI verifier in `p3-fri` did not validate prover-supplied `log_arity` values or the total reduction schedule against system limits (`Val::TWO_ADICITY`, `usize::BITS`) or the expected input dimensions. This allowed a malicious prover to trigger panics (DoS) by providing extremely large arities or mismatched heights that caused out-of-bounds bit-shifts or invalid field generator sampling.

**Learning:** Verifiers must explicitly bound all metadata derived from the proof before using it in arithmetic or indexing. In FRI, the codeword height is a function of the trace length and blowup; if the prover claims a different height, it can lead to inconsistent state or panics in the folding loop.

**Prevention:** Use `checked_add` for all log-dimension calculations. Enforce that each `log_arity > 0` and within `max_log_arity`. Validate the final `log_global_max_height` against field-specific constants and the actual heights of committed input matrices.
