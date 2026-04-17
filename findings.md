# FrodoKEM Parameter Audit — Findings

**Date:** April 17, 2026  
**Scope:** `src/math.ts`, `src/main.ts` — keygen, encapsulation, and decapsulation exhibits

---

## Result: All parameters are full spec-accurate

No reduced or toy parameters are used in the keygen, encapsulation, or decapsulation exhibits.

---

## Parameter Verification

| Parameter Set | n | q | Public Key (B) | Private Key (B) | Ciphertext (B) | σ | Max Error | Status |
|---|---|---|---|---|---|---|---|---|
| FrodoKEM-640 | 640 | 2¹⁵ (32768) | 9,616 ✓ | 19,888 ✓ | 9,720 ✓ | 2.8 ✓ | 12 | Spec-accurate |
| FrodoKEM-976 | 976 | 2¹⁶ (65536) | 15,632 ✓ | 31,296 ✓ | 15,744 ✓ | 2.3 ✓ | 10 | Spec-accurate |
| FrodoKEM-1344 | 1,344 | 2¹⁶ (65536) | 21,520 ✓ | 43,088 ✓ | 21,632 ✓ | 1.4 ✓ | 6 | Spec-accurate |

All n values, q values, byte sizes, σ values, and max error bounds match the FrodoKEM specification exactly.

---

## Where Parameters Are Defined

- **`src/math.ts`** — `FRODO` record contains all three parameter sets (`frodo640`, `frodo976`, `frodo1344`) with spec-accurate values.
- **`src/main.ts`** — Keygen, encapsulation, and decapsulation exhibits consume parameters via `FRODO[state.selectedParam]`. Default selection is `frodo976`, with a dropdown for all three sets.

---

## Toy Parameters (Intentionally Small — Not Changed)

| Exhibit | Parameters | Purpose |
|---|---|---|
| LWE Problem (Tab 1) | n=3, q=97, e ∈ {-1, 0, 1} | First-principles LWE pedagogy |
| Decryption Failure Demo | q=17, half=8 | Illustrates how oversized errors break correctness |
| Failure Probability Chart | q=17, maxErr 1–8 | Shows failure rate cliff as error magnitude grows |

These are intentionally small for interactive teaching and are fully isolated from the keygen/encap/decap exhibits.

---

## Actions Taken

- **No parameter changes were needed.** All keygen/encap/decap exhibits already use full FrodoKEM parameter sets.
- Confirmation comment blocks added to the top of `src/math.ts` and `src/main.ts` documenting spec accuracy.

---

## Exhibit Architecture Note

The keygen/encap/decap exhibits are conceptual/symbolic: they generate correctly-sized random byte arrays matching spec sizes and derive shared secrets via SHA-256. They do not implement the full FrodoKEM internal algebra (matrix expansion from SHAKE-128, noise sampling into S/E matrices, etc.). This is appropriate for an interactive educational demo — the exhibits accurately represent the size and structure properties of real FrodoKEM operations.
