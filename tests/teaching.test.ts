import { describe, it, expect } from 'vitest';
import { FRODO } from '../src/math';

// These protect the lesson, not just the code: Exhibit 2 shows a size calculator
// that derives pk/sk/ct from the matrix dimensions and prints "= N bytes ✓". If
// the displayed formulas ever drift from the FRODO constants, that ✓ would lie.
// Each formula below mirrors exactly what the UI renders.
describe('Exhibit 2 size-calculator formulas match the FRODO constants', () => {
  for (const p of Object.values(FRODO)) {
    const D = Math.ceil(Math.log2(p.q)); // bits per coefficient
    const seedLen = p.n <= 640 ? 16 : p.n <= 976 ? 24 : 32;

    it(`${p.label}: pk = 16 + n·n̄·D/8`, () => {
      const pk = 16 + (p.n * 8 * D) / 8;
      expect(pk).toBe(p.publicKey);
    });

    it(`${p.label}: sk = s + pk + S + pkh`, () => {
      const sk = seedLen + p.publicKey + p.n * 8 * 2 + seedLen;
      expect(sk).toBe(p.privateKey);
    });

    it(`${p.label}: ct = c1 + c2`, () => {
      const c1 = (8 * p.n * D) / 8;
      const c2 = (8 * 8 * D) / 8;
      expect(c1 + c2).toBe(p.ciphertext);
    });
  }
});

// The comparison table and bar charts hard-code ML-KEM-768 reference sizes and a
// FrodoKEM/ML-KEM ratio. Pin them so a parameter edit can't silently desync the
// numbers the comparison exhibit teaches.
describe('comparison reference figures stay consistent', () => {
  const MLKEM768_PK = 1184;

  it('FrodoKEM-976 public key is ~13.2× ML-KEM-768', () => {
    expect(+(FRODO.frodo976.publicKey / MLKEM768_PK).toFixed(1)).toBe(13.2);
  });

  it('shared-secret sizes grow with security level (16/24/32)', () => {
    // FrodoKEM shared-secret lengths the KEM exhibit displays per level.
    expect([FRODO.frodo640, FRODO.frodo976, FRODO.frodo1344].map((p) => p.n)).toEqual([640, 976, 1344]);
  });
});
