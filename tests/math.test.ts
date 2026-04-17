import { describe, it, expect } from 'vitest';
import {
  mod,
  modInv,
  vecDot,
  solve3x3Mod97,
  buildToyLweSamples,
  normalPdfLike,
  computeFailureProbabilities,
  formatHex,
  hexPreview,
  concat,
  renderCtDiff,
  FRODO,
} from '../src/math';

describe('mod', () => {
  it('returns positive remainder for positive inputs', () => {
    expect(mod(10, 97)).toBe(10);
    expect(mod(100, 97)).toBe(3);
  });

  it('wraps negative numbers into positive range', () => {
    expect(mod(-1, 97)).toBe(96);
    expect(mod(-97, 97) === 0).toBe(true); // -0 and 0 are equal via ===
    expect(mod(-3, 17)).toBe(14);
  });

  it('returns 0 for multiples', () => {
    expect(mod(0, 97)).toBe(0);
    expect(mod(97, 97)).toBe(0);
  });
});

describe('modInv', () => {
  it('computes modular inverse correctly', () => {
    // 3 * 65 = 195 = 2*97 + 1 => 3^{-1} mod 97 = 65
    expect(mod(3 * modInv(3, 97), 97)).toBe(1);
    expect(mod(7 * modInv(7, 97), 97)).toBe(1);
    expect(mod(50 * modInv(50, 97), 97)).toBe(1);
  });

  it('throws for non-invertible elements', () => {
    expect(() => modInv(0, 97)).toThrow('No modular inverse');
  });

  it('works for small primes', () => {
    expect(mod(2 * modInv(2, 5), 5)).toBe(1);
    expect(mod(3 * modInv(3, 7), 7)).toBe(1);
  });
});

describe('vecDot', () => {
  it('computes dot product mod q', () => {
    expect(vecDot([1, 0, 0], [5, 6, 7], 97)).toBe(5);
    expect(vecDot([2, 3, 4], [10, 20, 30], 97)).toBe(mod(2 * 10 + 3 * 20 + 4 * 30, 97));
  });

  it('handles wrap-around', () => {
    expect(vecDot([50, 50, 50], [50, 50, 50], 97)).toBe(mod(7500, 97));
  });
});

describe('solve3x3Mod97', () => {
  it('recovers a known secret from noiseless samples', () => {
    const secret: [number, number, number] = [3, 7, 11];
    const samples = buildToyLweSamples(secret, false);
    const solved = solve3x3Mod97(samples);
    expect(solved).not.toBeNull();
    expect(solved).toEqual(secret);
  });

  it('returns null for singular systems', () => {
    const samples = [
      { a: [0, 0, 0] as [number, number, number], b: 0, e: 0 },
      { a: [0, 0, 0] as [number, number, number], b: 0, e: 0 },
      { a: [0, 0, 0] as [number, number, number], b: 0, e: 0 },
    ];
    expect(solve3x3Mod97(samples)).toBeNull();
  });
});

describe('buildToyLweSamples', () => {
  it('produces 3 noiseless samples with zero error', () => {
    const secret: [number, number, number] = [5, 10, 15];
    const samples = buildToyLweSamples(secret, false);
    expect(samples).toHaveLength(3);
    samples.forEach((s) => {
      expect(s.e).toBe(0);
      expect(s.b).toBe(vecDot(s.a, secret, 97));
    });
  });

  it('produces 5 noisy samples', () => {
    const secret: [number, number, number] = [5, 10, 15];
    const samples = buildToyLweSamples(secret, true, 2);
    expect(samples).toHaveLength(5);
    samples.forEach((s) => {
      expect(Math.abs(s.e)).toBeLessThanOrEqual(2);
    });
  });

  it('verifies b = <a, s> + e mod 97', () => {
    const secret: [number, number, number] = [42, 13, 71];
    const samples = buildToyLweSamples(secret, true, 5);
    samples.forEach((s) => {
      expect(s.b).toBe(mod(vecDot(s.a, secret, 97) + s.e, 97));
    });
  });
});

describe('normalPdfLike', () => {
  it('peaks at x=0', () => {
    const peak = normalPdfLike(0, 2.8);
    expect(peak).toBe(1);
  });

  it('is symmetric', () => {
    expect(normalPdfLike(3, 2.8)).toBeCloseTo(normalPdfLike(-3, 2.8), 10);
  });

  it('decreases away from center', () => {
    expect(normalPdfLike(0, 2.8)).toBeGreaterThan(normalPdfLike(1, 2.8));
    expect(normalPdfLike(1, 2.8)).toBeGreaterThan(normalPdfLike(5, 2.8));
  });
});

describe('computeFailureProbabilities', () => {
  it('returns 8 entries for maxErr 1..8', () => {
    const probs = computeFailureProbabilities();
    expect(probs).toHaveLength(8);
    expect(probs[0].maxErr).toBe(1);
    expect(probs[7].maxErr).toBe(8);
  });

  it('has monotonically non-decreasing failure rates', () => {
    const probs = computeFailureProbabilities();
    for (let i = 1; i < probs.length; i++) {
      expect(probs[i].rate).toBeGreaterThanOrEqual(probs[i - 1].rate);
    }
  });

  it('has zero or near-zero failure for small errors', () => {
    const probs = computeFailureProbabilities();
    // maxErr=1 with q=17, half=8: error ±1 should never cause failure
    expect(probs[0].rate).toBe(0);
  });

  it('has high failure rate for large errors', () => {
    const probs = computeFailureProbabilities();
    // maxErr=8 with q=17 means error can be ±8 = half of q, should cause many failures
    expect(probs[7].rate).toBeGreaterThan(0.3);
  });
});

describe('formatHex', () => {
  it('returns -- for null', () => {
    expect(formatHex(null)).toBe('--');
  });

  it('formats bytes as hex', () => {
    expect(formatHex(new Uint8Array([0, 255, 16]))).toBe('00ff10');
  });
});

describe('hexPreview', () => {
  it('shows first N bytes and truncation message', () => {
    const bytes = new Uint8Array(100);
    bytes[0] = 0xab;
    bytes[1] = 0xcd;
    const result = hexPreview(bytes, 4);
    expect(result).toContain('abcd0000');
    expect(result).toContain('[96 more bytes]');
  });
});

describe('concat', () => {
  it('concatenates two byte arrays', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5]);
    const result = concat(a, b);
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
  });

  it('handles empty arrays', () => {
    const a = new Uint8Array([]);
    const b = new Uint8Array([1]);
    expect(concat(a, b)).toEqual(new Uint8Array([1]));
    expect(concat(b, a)).toEqual(new Uint8Array([1]));
  });
});

describe('renderCtDiff', () => {
  it('returns empty for null inputs', () => {
    expect(renderCtDiff(null, null)).toBe('');
    expect(renderCtDiff(null, new Uint8Array([1]))).toBe('');
    expect(renderCtDiff(new Uint8Array([1]), null)).toBe('');
  });

  it('marks tampered bytes with span.tampered', () => {
    const pre = new Uint8Array([0x00, 0xff]);
    const post = new Uint8Array([0x00, 0xfe]);
    const html = renderCtDiff(pre, post);
    expect(html).toContain('00');
    expect(html).toContain('<span class="tampered">fe</span>');
  });

  it('leaves identical bytes unspanned', () => {
    const pre = new Uint8Array([0xab, 0xcd]);
    const post = new Uint8Array([0xab, 0xcd]);
    const html = renderCtDiff(pre, post);
    expect(html).toBe('abcd');
    expect(html).not.toContain('tampered');
  });
});

describe('FRODO params', () => {
  it('has three parameter sets', () => {
    expect(Object.keys(FRODO)).toHaveLength(3);
  });

  it('frodo640 has correct public key size', () => {
    expect(FRODO.frodo640.publicKey).toBe(9616);
  });

  it('frodo976 has correct ciphertext size', () => {
    expect(FRODO.frodo976.ciphertext).toBe(15744);
  });

  it('frodo1344 has correct PQ security bits', () => {
    expect(FRODO.frodo1344.pqBits).toBe(207);
  });

  it('all sets have publicKey > privateKey is false (private > public)', () => {
    for (const p of Object.values(FRODO)) {
      expect(p.privateKey).toBeGreaterThan(p.publicKey);
    }
  });
});
