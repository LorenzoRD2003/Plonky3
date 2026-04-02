## 2025-02-14 - [HIGH] Verifier panics on adversarial FRI metadata

**Vulnerability:** The FRI and Circle FRI verifiers lacked validation for prover-supplied metadata like `log_arity` and the total reduction height. An attacker could provide extremely large values, causing the verifier to:
1. Panic due to integer overflow in height calculations.
2. OOM by attempting to allocate massive vectors (`vec![EF::ZERO; 1 << log_arity]`).
3. Panic during domain generation if the requested degree exceeded the field's `TWO_ADICITY`.
4. Underflow when calculating bit-shifts for smaller matrices if `log_global_max_height` was maliciously small.

**Learning:** Verifiers must never trust prover-supplied dimensions or bit-counts that drive memory allocation or hardware-sensitive operations (like bit-shifts). In Plonky3, `log_arity` is particularly dangerous as it is used for both.

**Prevention:**
1. Use checked arithmetic for all metadata derived from the proof.
2. Explicitly validate that proof-supplied values are within expected parameters (e.g., `params.max_log_arity`) and system limits (e.g., `usize::BITS`).
3. Validate metadata against cryptographic bounds early (e.g., `TWO_ADICITY` for Two-Adic PCS, or field order bits for Circle PCS).
