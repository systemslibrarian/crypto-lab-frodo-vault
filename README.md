# crypto-lab-frodo-vault

## What It Is

FrodoKEM is a post-quantum Key Encapsulation Mechanism (KEM) built on the plain Learning With Errors (LWE) problem — no ring or module structure. Unlike ML-KEM (FIPS 203), which gains speed from structured polynomial arithmetic, FrodoKEM relies only on the most conservative lattice hardness assumption: unstructured LWE, introduced by Regev (2005). This demo runs **real FrodoKEM** — genuine key generation, encapsulation, and decapsulation from [liboqs](https://github.com/open-quantum-safe/liboqs) (the Open Quantum Safe project), compiled to WebAssembly via [`@oqs/liboqs-js`](https://www.npmjs.com/package/@oqs/liboqs-js) — for all three security levels (640, 976, 1344), plus real ML-KEM-768 for the hybrid walkthrough. Shared secrets match because the LWE math agrees, a tampered ciphertext genuinely fails decapsulation (FrodoKEM's implicit rejection), and the speed comparison is measured live in your browser. It is an educational tool: keys are ephemeral and in-memory — not a key-management system.

## When to Use It

- **Long-term archive secrecy with maximum conservatism** — FrodoKEM avoids algebraic structure that could be vulnerable to future attacks, making it suitable when the threat horizon exceeds 20 years.
- **Hybrid KEM deployments** — Combine FrodoKEM with ML-KEM so that security holds if either assumption survives. The demo includes a hybrid KEM walkthrough.
- **Understanding LWE fundamentals** — The toy LWE exhibit (n=3, q=97) lets you explore modular arithmetic, noise injection, and Gaussian elimination interactively.
- **Comparing post-quantum KEM trade-offs** — Side-by-side size, speed, and security comparisons between FrodoKEM and ML-KEM with real specification data.
- **Do not use when bandwidth or key size is constrained** — FrodoKEM-976 public keys are ~15 KB versus ~1.2 KB for ML-KEM-768. For TLS or constrained devices, ML-KEM is the standard choice.

## Live Demo

[https://systemslibrarian.github.io/crypto-lab-frodo-vault/](https://systemslibrarian.github.io/crypto-lab-frodo-vault/)

Seven interactive exhibits: toy LWE problem with adjustable noise and animated matrix multiplication, real FrodoKEM key generation with a parameter size calculator, real encapsulation/decapsulation with a working tamper-rejection test, FrodoKEM vs ML-KEM comparison with a live in-browser benchmark and a real hybrid KEM derivation, error distribution sampling with failure probability visualization, post-quantum KEM landscape overview, and a sourced analysis of the global structured-vs-structureless lattice standards divide.

Each exhibit is built as a lesson, not just a panel: a stated learning goal up top, predict-before-you-run checkpoints with immediate feedback, a "you should now understand" recall summary at the bottom, a toy-LWE→real-FrodoKEM bridge, a stateful KEM data-flow diagram, a glossary, a common-misconceptions section, and evidence-category labels (published spec / standards decision / public statement / interpretation / unknown) on the geopolitics exhibit.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-frodo-vault
cd crypto-lab-frodo-vault
npm install
npm run dev
```

## Part of the Crypto-Lab Suite

> One of 60+ live browser demos at [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*