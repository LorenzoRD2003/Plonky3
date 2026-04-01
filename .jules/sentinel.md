## 2025-01-24 - FRI Verifier Panic and Soundness Hardening
**Vulnerability:** The FRI verifier did not sufficiently validate prover-supplied metadata, such as folding arities (`log_arity`) and the resulting reduction schedule. This allowed an adversarial prover to trigger panics via integer underflow in `bits_reduced` calculations, out-of-bounds bit sampling in the challenger (if `log_global_max_height` exceeded field order bits), or sampling non-existent two-adic generators (if `log_global_max_height > Val::TWO_ADICITY`). Furthermore, a mismatch between the proof's reduction height and the input matrix heights was not explicitly rejected, potentially leading to unsound verification or logic errors.

**Learning:** Verifiers often rely on internal algebraic utility functions (like `two_adic_generator` or `sample_bits`) that have implicit preconditions (e.g., `bits <= TWO_ADICITY`). If these preconditions are not checked against untrusted proof data at the verifier's entry point, they manifest as panics in production/release builds, causing Denial-of-Service. Additionally, binding the proof structure to the expected instance parameters (matrix heights) is critical for soundness.

**Prevention:** Always explicitly validate prover-provided dimensions, degrees, and arities against:
1. System limits (`usize::BITS`).
2. Field-specific limits (`Val::bits()`, `Val::TWO_ADICITY`).
3. Protocol parameters (`params.max_log_arity`).
4. Expected instance dimensions (matrix heights in `commitments_with_opening_points`).
Use `checked_add` and `checked_mul` for all arithmetic involving these untrusted values.
