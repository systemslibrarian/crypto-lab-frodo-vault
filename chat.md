# Suggestions To Make Frodo Vault A Gold-Standard Teaching Demo

## Short Verdict

This is already well above the usual crypto demo: it runs real FrodoKEM and ML-KEM through liboqs/WASM, separates toy math from production operations, shows tamper rejection, includes citations, and has explicit reality checks. To make it the gold standard for what it teaches, the next step is not more cryptographic machinery. The next step is stronger pedagogy: learner progression, active recall, provenance, benchmark rigor, and clearer conceptual transfer from toy LWE to real FrodoKEM.

The best version of this demo should make a learner leave with five durable ideas:

1. LWE is linear algebra made hard by small errors.
2. FrodoKEM deliberately uses plain LWE with no ring/module structure.
3. That conservatism costs bytes and speed.
4. Real KEMs succeed or fail through exact encapsulation/decapsulation checks, not through decorative hashes.
5. Hybrid deployment is a practical risk-management strategy, not magic.

## Highest-Impact Improvements

### 1. Add A Guided Learning Path

Right now the seven exhibits are strong individually, but the learner can treat them as disconnected panels. Add a visible progression layer that says what each exhibit is supposed to teach and what question it answers.

Recommended structure:

| Step | Exhibit | Learner Question |
|---|---|---|
| 1 | LWE Problem | Why does adding error make linear algebra hard? |
| 2 | Key Generation | Where do A, S, E, and B appear in a real keypair? |
| 3 | Encap / Decap | How do two parties derive the same secret without sending it? |
| 4 | Frodo vs ML-KEM | What does avoiding structure cost? |
| 5 | Error Distribution | Why must errors be small but unpredictable? |
| 6 | PQ Landscape | Why is FrodoKEM not the default? |
| 7 | Global Divide | Why do standards bodies disagree about structure? |

Add a compact "You should now understand..." summary at the end of each exhibit. This is the single highest-value teaching improvement because it turns the demo from an exhibit gallery into a lesson.

### 2. Add Checkpoints With Immediate Feedback

The demo should ask the learner to predict before revealing. This makes the math stick.

Suggested checkpoints:

- Before solving noiseless LWE: "Will Gaussian elimination recover the secret exactly?"
- Before solving noisy LWE: "Will the first three equations agree with the remaining samples?"
- Before tampering: "After one flipped ciphertext bit, will Alice recover Bob's same secret?"
- Before benchmarking: "Which scheme do you expect to have the larger key? Which do you expect to be faster?"
- Before the failure chart: "What happens when error magnitude approaches half the modulus?"

Keep these tiny: one question, two or three choices, immediate explanation. The point is active recall, not a quiz page.

### 3. Make The Toy-To-Real Bridge Explicit

The current reality panels correctly say what is toy and what is real. The missing gold-standard move is a side-by-side mapping from the toy symbols to the real scheme.

Add a table like this near Exhibit 1 or Exhibit 2:

| Toy LWE Demo | Real FrodoKEM |
|---|---|
| n = 3 | n = 640, 976, or 1344 |
| q = 97 | q = 2^15 or 2^16 |
| one secret vector s | secret matrix S with n x nbar entries |
| random row a | huge matrix A expanded from seed_A |
| b = <a,s> + e | B = A*S + E |
| hand-solvable equations | full-size LWE instance |

This table prevents a common learner mistake: thinking the toy demo is a miniature implementation of all FrodoKEM internals rather than a conceptual slice.

### 4. Add A Visual Data-Flow Diagram For KEM

The encapsulation/decapsulation text is accurate, but the flow is dense. Add a compact diagram that shows what crosses the wire and what stays private.

Minimum diagram content:

- Alice keeps `sk`, publishes `pk`.
- Bob uses `pk` to produce `ct` and `SS_bob`.
- Alice uses `ct + sk` to recover `SS_alice`.
- Only `pk` and `ct` cross the wire.
- `SS_bob == SS_alice` only for valid ciphertexts.

This should be visual and stateful: after each button click, highlight the step just completed.

### 5. Add "What Changed?" Views For Real Operations

The real cryptographic path is the demo's strongest asset. Surface it more clearly.

For key generation:

- Show public-key length and secret-key length as already done.
- Add a short fingerprint of the public key, not just a long preview.
- On repeated keygen, show "new keypair" by comparing fingerprints.

For encapsulation:

- Show ciphertext fingerprint.
- Show shared-secret fingerprint.
- Explain that the shared secret is not encrypted and sent; both sides derive it.

For tamper rejection:

- Keep the byte diff.
- Add a clear before/after secret fingerprint comparison.
- Say explicitly: decapsulation does not throw; it returns an unrelated implicit-rejection secret.

This teaches behavior without overwhelming learners with raw hex.

### 6. Strengthen Benchmark Rigor

The live benchmark is excellent, but gold-standard teaching should make measurement limitations obvious.

Add:

- Warm-up runs before recorded samples.
- Display sample count, median, and maybe min/max.
- Label first-run WASM loading separately from operation timing.
- Include a note that browser measurements are useful for ratios, not publication-grade performance claims.

The current text already says device-dependent. The improvement is to expose enough methodology that learners trust the benchmark and understand why it varies.

### 7. Add A Threat-Model Panel

The demo repeatedly says "not for production," which is good. Add one concise threat-model panel that teaches what the demo does and does not protect.

Suggested rows:

| Question | Answer |
|---|---|
| Does this show real FrodoKEM math? | Yes, through liboqs/WASM. |
| Does this securely manage keys? | No. Keys live in browser memory only. |
| Does this prove browser execution is constant-time? | No. |
| Does tamper rejection mean authentication? | No. It means invalid ciphertexts do not reveal useful key material. |
| Can I use this code to protect files? | No. Use a maintained cryptographic library and protocol. |

This would reduce the chance that learners overgeneralize from demo success to deployment safety.

### 8. Separate Fact, Interpretation, And Geopolitical Context

Exhibit 7 is interesting, but it is the easiest place for a teaching demo to lose rigor. Keep it, but tighten the evidence categories.

Recommended labels:

- Published specification
- Standards-body decision
- Public statement
- Interpretation / strategic analysis
- Unknown / not yet published

For S-Cloud+, the demo should continue to say clearly that no public cryptographic specification is available. The gold-standard version should make that caveat visually hard to miss wherever S-Cloud+ is discussed.

### 9. Add Source Links At The Claim Level

The references section is good. Gold-standard teaching benefits from more claim-level traceability.

Prioritize source links for:

- FrodoKEM parameter sizes.
- ML-KEM-768 sizes.
- NIST status: ML-KEM standardized, FrodoKEM alternate/non-standardized, HQC selected as backup.
- The FrodoKEM failure probability target.
- Any claims about S-Cloud+ or Chinese PQC standardization.

This does not need academic overkill. The goal is that a skeptical learner can click from a major claim to its source.

### 10. Add A "Common Misconceptions" Section

This would be very high teaching value and low implementation cost.

Recommended misconceptions:

- "FrodoKEM is more secure than ML-KEM in every sense." Correction: it is more conservative in its assumption, but not the NIST default and not automatically better for every deployment.
- "No ring structure means no mathematical structure at all." Correction: it still has lattice/LWE structure; it avoids ring/module algebraic structure.
- "The shared secret is sent inside the ciphertext." Correction: the ciphertext lets Alice derive the same secret; the secret itself is not sent.
- "A browser demo using real crypto is production-safe." Correction: real primitives are not the same as a secure protocol or key-management system.
- "A tampered ciphertext failing means FrodoKEM authenticates the sender." Correction: KEM validity is not sender authentication.

## Concrete Feature Ideas

### Add A Progress Meter

Track which exhibits the learner has interacted with:

- Generated LWE samples.
- Solved noiseless system.
- Observed noisy inconsistency.
- Generated real keypair.
- Completed encapsulation/decapsulation.
- Observed tamper mismatch.
- Ran benchmark.
- Ran hybrid derivation.
- Sampled error distribution.

Then show a small "lesson complete" state. This turns exploration into accomplishment without making the app feel like schoolwork.

### Add A Glossary Drawer

Terms worth defining inline:

- KEM
- LWE
- Plain LWE
- Ring-LWE
- Module-LWE
- Ciphertext
- Shared secret
- Encapsulation
- Decapsulation
- Implicit rejection
- CCA security
- KDF
- WASM

Short definitions are enough. The goal is to keep beginners from falling out of the lesson.

### Add Copyable Experiment Results

After running a benchmark or KEM round-trip, allow a learner to copy a small result block:

```text
FrodoKEM-976 in browser
pk: 15632 bytes
ct: 15744 bytes
shared secret: 24 bytes
encaps: X ms
decaps: Y ms
tamper test: mismatch as expected
```

This makes the demo useful for classrooms, workshops, and writeups.

### Add Deterministic Toy Mode

For Exhibit 1, add a "Use fixed classroom example" button. Random samples are good for exploration, but deterministic examples are better for instruction, screenshots, and debugging.

The fixed example should include:

- A known secret.
- Three noiseless equations.
- Five noisy equations.
- A worked residual calculation.

### Add A Worked Example Below The Toy Solver

Show one equation fully expanded:

```text
a = [12, 44, 7], s = [3, 7, 11], e = -1
b = 12*3 + 44*7 + 7*11 - 1 mod 97
b = 420 mod 97 = 32
```

This makes the abstract formula tangible.

### Add Error Budget Visualization

The failure chart is useful. Make the central lesson even clearer:

- Draw decision regions around 0 and q/2.
- Show the message point moving as error is added.
- Mark the boundary where decoding flips.

This would teach correctness more directly than a histogram alone.

## Content Edits I Would Make

### Tighten The Hero Claim

Current message is strong. The gold-standard version should front-load the learner promise:

> Learn why FrodoKEM chooses plain LWE, watch real liboqs FrodoKEM run in your browser, and see the exact cost of avoiding ring/module structure.

That tells the learner what they will understand, not only what the project is.

### Clarify "Conservative"

Use "conservative assumption" consistently, not "more secure" as a blanket claim. The distinction matters.

Good phrasing:

> FrodoKEM is conservative because its security rests on plain LWE without ring/module algebraic structure. That does not make it the best deployment choice everywhere; it makes the assumption surface smaller and the implementation cost larger.

### Clarify FrodoKEM Status

Use one consistent status phrase:

> FrodoKEM was evaluated in the NIST PQC process but was not selected as the primary KEM standard; ML-KEM is FIPS 203. FrodoKEM remains valuable as a conservative, publicly specified alternative.

Avoid wording that could make learners think FrodoKEM is itself a finalized NIST standard.

### Make Hybrid Claims Precise

The current hybrid text is mostly right. Make it slightly more formal:

> In a robust hybrid combiner, the resulting secret should remain secure if at least one component KEM remains secure, assuming the combiner is domain-separated and used inside a sound protocol.

The demo's `SHA-256(SS_mlkem || SS_frodo)` is fine for teaching, but production protocols should use specified hybrid combiners.

## Engineering Improvements That Support Teaching

### Add Tests For Educational Invariants

The existing tests cover math and real round-trips. Add tests for claims the UI teaches:

- Parameter table values match `FRODO` constants.
- Size calculator formulas produce displayed key/ciphertext sizes.
- Tamper state always changes the ciphertext and clears any stale success state.
- Toy noisy solve reports residuals against all samples, not just the first three.
- Hybrid derivation changes when either component secret changes.

These tests protect the lesson, not just the code.

### Reduce Long Template Risk

`src/main.ts` currently contains a very large HTML template. That is workable for a small demo, but gold-standard teaching content will grow. Consider splitting by exhibit:

- `renderLwePanel`
- `renderKeygenPanel`
- `renderKemPanel`
- `renderComparePanel`
- `renderErrorsPanel`
- `renderLandscapePanel`
- `renderDividePanel`

Do this only when adding new teaching features; no need to refactor for its own sake. The reason to split is to make future educational copy easier to review and test.

### Add Link Checking

Because the demo relies on citations, add a lightweight link-check script for references and cross-demo links. A gold-standard teaching artifact should not have stale citations.

### Add Accessibility Regression Checks

The demo already has good accessibility basics: skip link, tab roles, keyboard navigation, focus styles, reduced-motion handling, captions, and live regions. To lock that in, add automated checks with Playwright + axe or similar.

Focus on:

- Tab navigation works.
- Active tab has correct `aria-selected` and `tabindex`.
- Hidden panels are not focusable.
- Live status messages update after crypto operations.
- Color contrast remains valid in light and dark themes.

## Suggested Priority Order

1. Add guided learning objectives and end-of-exhibit takeaways.
2. Add toy-to-real mapping table.
3. Add prediction checkpoints with immediate feedback.
4. Add KEM data-flow diagram.
5. Improve benchmark methodology display.
6. Add misconception and glossary sections.
7. Tighten Exhibit 7 evidence labels and S-Cloud+ caveats.
8. Add tests for educational invariants.
9. Split renderer functions as the content grows.
10. Add link and accessibility regression checks.

## What I Would Not Change First

- I would not replace liboqs/WASM. That is the demo's strongest credibility feature.
- I would not add deeper FrodoKEM internals before adding learner checkpoints. More detail without feedback will not teach as well.
- I would not make Exhibit 7 more dramatic. It should become more carefully sourced, not more forceful.
- I would not remove the toy exhibits. They are essential; they just need a stronger bridge to the real parameter sets.
- I would not over-optimize the UI before tightening the learning path.

## Final Gold-Standard Bar

This becomes a gold-standard FrodoKEM teaching demo when a learner can do three things without outside explanation:

1. Explain why noisy linear equations are hard while noiseless ones are easy.
2. Explain why FrodoKEM is larger and slower than ML-KEM.
3. Explain what the real browser operations prove, what they do not prove, and why hybrid KEMs are used.

The current implementation already has the cryptographic credibility. The biggest opportunity is to add a teaching spine: predict, run, observe, explain, verify.