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

Seven exhibits: the LWE problem from first principles with toy interactive
demo, FrodoKEM key generation with real parameter sizes visualized, full
encapsulation and decapsulation with tamper detection, side-by-side
FrodoKEM vs ML-KEM comparison with decision tree, error distribution
visualizer with decryption failure demo, FrodoKEM in the full PQ KEM
landscape with hybrid recommendation, and the global PQC standards divide —
structureless vs algebraic lattices, China's S-Cloud+, and why even NIST
hedged with HQC.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-frodo-vault
cd crypto-lab-frodo-vault
npm install
npm run dev
```

## 5. Part of the Crypto-Lab Suite

Part of [crypto-lab](https://systemslibrarian.github.io/crypto-lab/) —
browser-based cryptography demos spanning 2,500 years of cryptographic
history to NIST FIPS 2024 post-quantum standards.

---

So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31