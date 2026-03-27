## 2025-05-14 - Hardening FRI Verifier against malformed metadata
**Vulnerability:** The FRI verifier in `p3-fri` lacked validation of prover-supplied `log_arities`. This allowed a hostile prover to trigger panics via:
1. Arithmetic overflow/underflow in height calculations.
2. Out-of-bounds bit-shifts in `sample_bits` (e.g., `log_arity = 100`).
3. Large domain generator sampling panics (e.g., `log_height > TWO_ADICITY`).
4. Resource exhaustion via massive vector allocations (`1 << log_arity`).

**Learning:** Verifiers must treat all metadata in the proof (like arity schedules, degree bits, etc.) as untrusted input. These values must be validated against both absolute limits (like `usize::BITS` or field `TWO_ADICITY`) and expected values derived from the input dimensions of the claim being verified.

**Prevention:**
1. Explicitly validate that each `log_arity` is non-zero and within the configured `max_log_arity`.
2. Re-calculate the expected global height from input matrices and enforce that the proof's reduction schedule matches it exactly.
3. Use `checked_add` and other safe arithmetic for any proof-controlled dimensions.
4. Validate that calculated heights do not exceed field-specific limits (`TWO_ADICITY`) before sampling generators.
