# crypto-lab-frodo-vault

## 1. What It Is

Frodo Vault demonstrates FrodoKEM (Bos et al., 2016) — the conservative
post-quantum Key Encapsulation Mechanism based on plain Learning With
Errors (LWE), with no ring or module structure. While ML-KEM (NIST FIPS 203)
uses Module-LWE for efficiency, FrodoKEM deliberately avoids ring structure
to rely on the most conservative LWE hardness assumption. The cost is larger
keys (~15KB public key for FrodoKEM-976 vs ~1KB for ML-KEM-768). The benefit
is security that does not depend on ring-LWE remaining unbroken — making
FrodoKEM the right choice for highest-assurance, long-lived secrets.
Exhibit 7 places FrodoKEM in the context of the emerging global standards
divide: China's preference for structureless lattice algorithms (S-Cloud+)
versus NIST's algebraic lattice standards (ML-KEM), and what that divergence
means for the future of post-quantum cryptography.

## 2. When to Use It

- ✅ Protecting data that must remain secret for 20+ years
- ✅ Highest-assurance environments requiring maximum cryptographic conservatism
- ✅ Hybrid KEM with ML-KEM: ML-KEM-768 + FrodoKEM-976 for security against
	either being broken (Amazon s2n approach)
- ✅ Classified or government communications requiring NIST Round 4 alternate
	acceptance
- ❌ General-purpose post-quantum KEM for TLS or web applications —
	use ML-KEM-768 (FIPS 203) instead
- ❌ Constrained environments where bandwidth or storage is limited —
	15KB keys and ciphertexts are a real cost
- ❌ High-frequency key exchange — FrodoKEM is ~10-50× slower than ML-KEM

## 3. Live Demo

Link: https://systemslibrarian.github.io/crypto-lab-frodo-vault/

**Seven exhibits:**

1. **LWE Problem** — interactive toy demo (n=3, q=97), adjustable noise slider,
   animated A·s + e matrix multiplication, Gaussian elimination solver
2. **Key Generation** — real FrodoKEM parameter sizes, public key bar chart
   (param-aware), keypair generation timing
3. **Encap / Decap** — full KEM flow with tamper detection, ciphertext diff
   viewer highlighting tampered bytes
4. **Frodo vs ML-KEM** — side-by-side benchmark, decision tree, hybrid KEM
   walkthrough combining ML-KEM-768 + FrodoKEM-976
5. **Error Distribution** — histogram of 1000 sampled errors, toy decryption
   failure demo, failure probability chart showing the error-magnitude cliff
6. **PQ Landscape** — FrodoKEM in the full post-quantum KEM landscape with
   cross-demo links and hybrid recommendation
7. **The Global Divide** — structureless vs algebraic lattices, China's S-Cloud+,
   NIST's HQC hedge, and FrodoKEM as the bridge

**Interactive features:**

- URL hash routing — link directly to any exhibit (e.g. `#kem`, `#divide`)
- Keyboard navigation — arrow keys cycle tabs, Home/End jump to first/last
- Theme toggle — dark/light mode with localStorage persistence
- Collapsible sections — expandable detail panels that persist across interactions
- Animated matrix multiplication — step-by-step A·s + e = b mod q visualization
- Noise magnitude slider — adjust LWE error from 0 to 48).
- Ciphertext diff viewer — highlights tampered bytes in red after tampering
- Failure probability chart — bar chart showing the sharp correctness cliff
- Hybrid KEM walkthrough — derive combined secret from ML-KEM + FrodoKEM
- Print stylesheet — clean output for PDF/paper
- Noscript fallback — message for JS-disabled browsers
- 33 unit tests covering all core math and utility functions

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-frodo-vault
cd crypto-lab-frodo-vault
npm install
npm run dev
```

## 5. Tests

```bash
npm test
```

33 tests covering modular arithmetic, LWE sample generation, Gaussian
elimination solver, failure probabilities, hex formatting, and ciphertext
diff rendering.

## 6. Part of the Crypto-Lab Suite

Part of [crypto-lab](https://systemslibrarian.github.io/crypto-lab/) —
browser-based cryptography demos spanning 2,500 years of cryptographic
history to NIST FIPS 2024 post-quantum standards.

---

So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31