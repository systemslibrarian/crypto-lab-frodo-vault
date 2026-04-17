# crypto-lab-frodo-vault

## What It Is

FrodoKEM is a post-quantum Key Encapsulation Mechanism (KEM) built on the plain Learning With Errors (LWE) problem — no ring or module structure. Unlike ML-KEM (FIPS 203), which gains speed from structured polynomial arithmetic, FrodoKEM relies only on the most conservative lattice hardness assumption: unstructured LWE, introduced by Regev (2005). This demo provides an interactive browser-based simulation of FrodoKEM's key generation, encapsulation, and decapsulation flows with spec-accurate parameter sizes for all three security levels (640, 976, 1344). It is an educational tool, not a production cryptographic implementation.

## When to Use It

- **Long-term archive secrecy with maximum conservatism** — FrodoKEM avoids algebraic structure that could be vulnerable to future attacks, making it suitable when the threat horizon exceeds 20 years.
- **Hybrid KEM deployments** — Combine FrodoKEM with ML-KEM so that security holds if either assumption survives. The demo includes a hybrid KEM walkthrough.
- **Understanding LWE fundamentals** — The toy LWE exhibit (n=3, q=97) lets you explore modular arithmetic, noise injection, and Gaussian elimination interactively.
- **Comparing post-quantum KEM trade-offs** — Side-by-side size, speed, and security comparisons between FrodoKEM and ML-KEM with real specification data.
- **Do not use when bandwidth or key size is constrained** — FrodoKEM-976 public keys are ~15 KB versus ~1.2 KB for ML-KEM-768. For TLS or constrained devices, ML-KEM is the standard choice.

## Live Demo

[https://systemslibrarian.github.io/crypto-lab-frodo-vault/](https://systemslibrarian.github.io/crypto-lab-frodo-vault/)

Seven interactive exhibits: toy LWE problem with adjustable noise and animated matrix multiplication, simulated key generation with a parameter size calculator, encapsulation/decapsulation with tamper detection, FrodoKEM vs ML-KEM comparison with hybrid KEM derivation, error distribution sampling with failure probability visualization, post-quantum KEM landscape overview, and a sourced analysis of the global structured-vs-structureless lattice standards divide.

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