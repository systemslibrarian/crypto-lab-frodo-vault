// ============================================================================
// FrodoKEM Parameter Definitions & Mathematical Utilities
// ============================================================================
//
// WHAT IS REAL IN THIS FILE:
//   - All three FrodoKEM parameter sets match the specification exactly [4]:
//     FrodoKEM-640:  n=640,  q=2^15, pk=9616B,  sk=19888B, ct=9720B,  σ=2.8
//     FrodoKEM-976:  n=976,  q=2^16, pk=15632B, sk=31296B, ct=15744B, σ=2.3
//     FrodoKEM-1344: n=1344, q=2^16, pk=21520B, sk=43088B, ct=21632B, σ=1.4
//   - Modular arithmetic (mod, modInv, vecDot) is genuine
//   - Gaussian elimination (solve3x3Mod97) is real linear algebra over Z_97
//   - Error distribution sampling (normalPdfLike) uses spec-accurate σ
//
// WHAT IS EDUCATIONAL / TOY SCALE:
//   - buildToyLweSamples: n=3, q=97 (vs production n≥640, q≥2^15)
//   - computeFailureProbabilities: q=17 toy model for visualization
//   - These are intentionally small for interactive pedagogy
//
// References:
//   [1] Regev (2005), STOC.
//   [4] FrodoKEM Specification, 2021-06-04, frodokem.org — Table 1 (parameters),
//       Table 2 (security bounds; the C/Q/P columns used below).
// ============================================================================

export type LweSample = {
  a: [number, number, number];
  b: number;
  e: number;
};

export type FrodoId = 'frodo640' | 'frodo976' | 'frodo1344';

// SECURITY FIGURES: one source, one convention.
// All numbers below come from the FrodoKEM specification (2021-06-04), Table 2
// "Security bounds" [4]. Its LWE-security columns are labelled C / Q / P — classical,
// quantum, and plausible — and are core-SVP estimates of the best known lattice attack:
//
//   Frodo-640:  target level 1, C=145, Q=132, P=104
//   Frodo-976:  target level 3, C=210, Q=191, P=150
//   Frodo-1344: target level 5, C=275, Q=250, P=197
//
// Do NOT mix these with NIST security-category targets (AES-128/192/256 key search).
// The category is what a parameter set *aims at*; the core-SVP figures are what the
// submission team *estimates*. `nistLevel` records the target separately and is
// deliberately not expressed in bits, so the two conventions cannot be silently blended.
//
// `plausibleAttackBits` is the spec's deliberately pessimistic P column, which prices in
// speedups nobody has demonstrated. Other submissions (Kyber, for one) publish no
// equivalent column, so P must never be compared across schemes — compare C with C and
// Q with Q. This is the same convention the comparison table in main.ts now renders.
export type FrodoParams = {
  id: FrodoId;
  label: string;
  n: number;
  q: number;
  /** NIST security-strength category targeted by this set. A target, not a bit count. */
  nistLevel: 1 | 3 | 5;
  /** Core-SVP classical estimate, bits. Spec Table 2, column C. */
  coreSvpClassicalBits: number;
  /** Core-SVP quantum estimate, bits. Spec Table 2, column Q. */
  coreSvpQuantumBits: number;
  /** Core-SVP plausible-attack estimate, bits. Spec Table 2, column P. Not cross-comparable. */
  plausibleAttackBits: number;
  publicKey: number;
  privateKey: number;
  ciphertext: number;
  sigma: number;
  maxError: number;
};

export const FRODO: Record<FrodoId, FrodoParams> = {
  frodo640: {
    id: 'frodo640',
    label: 'FrodoKEM-640',
    n: 640,
    q: 2 ** 15,
    nistLevel: 1,
    coreSvpClassicalBits: 145,
    coreSvpQuantumBits: 132,
    plausibleAttackBits: 104,
    publicKey: 9616,
    privateKey: 19888,
    ciphertext: 9720,
    sigma: 2.8,
    maxError: 12,
  },
  frodo976: {
    id: 'frodo976',
    label: 'FrodoKEM-976',
    n: 976,
    q: 2 ** 16,
    nistLevel: 3,
    coreSvpClassicalBits: 210,
    coreSvpQuantumBits: 191,
    plausibleAttackBits: 150,
    publicKey: 15632,
    privateKey: 31296,
    ciphertext: 15744,
    sigma: 2.3,
    maxError: 10,
  },
  frodo1344: {
    id: 'frodo1344',
    label: 'FrodoKEM-1344',
    n: 1344,
    q: 2 ** 16,
    nistLevel: 5,
    coreSvpClassicalBits: 275,
    coreSvpQuantumBits: 250,
    plausibleAttackBits: 197,
    publicKey: 21520,
    privateKey: 43088,
    ciphertext: 21632,
    sigma: 1.4,
    maxError: 6,
  },
};

export function mod(a: number, q: number): number {
  const v = a % q;
  return v < 0 ? v + q : v;
}

export function modInv(a: number, q: number): number {
  let t = 0;
  let newT = 1;
  let r = q;
  let newR = mod(a, q);
  while (newR !== 0) {
    const quotient = Math.floor(r / newR);
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }
  if (r !== 1) throw new Error('No modular inverse');
  return mod(t, q);
}

export function vecDot(a: [number, number, number], b: [number, number, number], q: number): number {
  return mod(a[0] * b[0] + a[1] * b[1] + a[2] * b[2], q);
}

export function solve3x3Mod97(samples: LweSample[]): [number, number, number] | null {
  const q = 97;
  const m = samples.slice(0, 3).map((row) => [...row.a, row.b]);

  for (let col = 0; col < 3; col += 1) {
    let pivot = col;
    while (pivot < 3 && m[pivot][col] === 0) {
      pivot += 1;
    }
    if (pivot === 3) return null;
    if (pivot !== col) {
      [m[col], m[pivot]] = [m[pivot], m[col]];
    }

    const inv = modInv(m[col][col], q);
    for (let k = col; k < 4; k += 1) {
      m[col][k] = mod(m[col][k] * inv, q);
    }

    for (let r = 0; r < 3; r += 1) {
      if (r === col) continue;
      const factor = m[r][col];
      for (let k = col; k < 4; k += 1) {
        m[r][k] = mod(m[r][k] - factor * m[col][k], q);
      }
    }
  }

  return [m[0][3], m[1][3], m[2][3]];
}

export function buildToyLweSamples(
  secret: [number, number, number],
  includeNoise: boolean,
  noiseMag = 1,
  rng: () => number = () => crypto.getRandomValues(new Uint32Array(1))[0],
): LweSample[] {
  const q = 97;
  const count = includeNoise ? 5 : 3;
  const samples: LweSample[] = [];

  function randomInt(maxExclusive: number): number {
    if (maxExclusive <= 0) return 0;
    return rng() % maxExclusive;
  }
  function randomFromRange(min: number, max: number): number {
    return min + randomInt(max - min + 1);
  }

  while (samples.length < count) {
    const a: [number, number, number] = [randomFromRange(0, q - 1), randomFromRange(0, q - 1), randomFromRange(0, q - 1)];
    const e = includeNoise ? randomFromRange(-noiseMag, noiseMag) : 0;
    const b = mod(vecDot(a, secret, q) + e, q);
    samples.push({ a, b, e });
  }
  return samples;
}

export function normalPdfLike(x: number, sigma: number): number {
  return Math.exp(-(x * x) / (2 * sigma * sigma));
}

export function computeFailureProbabilities(
  rng: () => number = () => crypto.getRandomValues(new Uint32Array(1))[0],
): Array<{ maxErr: number; rate: number }> {
  const q = 17;
  const half = Math.floor(q / 2);
  const trials = 500;
  const results: Array<{ maxErr: number; rate: number }> = [];

  function randomInt(maxExclusive: number): number {
    if (maxExclusive <= 0) return 0;
    return rng() % maxExclusive;
  }
  function randomFromRange(min: number, max: number): number {
    return min + randomInt(max - min + 1);
  }

  for (let maxErr = 1; maxErr <= 8; maxErr++) {
    let failures = 0;
    for (let t = 0; t < trials; t++) {
      const m = randomInt(2);
      const e = randomFromRange(-maxErr, maxErr);
      const noisy = mod(m * half + e, q);
      const d0 = Math.min(mod(noisy, q), mod(-noisy, q));
      const d1 = Math.min(mod(noisy - half, q), mod(half - noisy, q));
      if ((d1 < d0 ? 1 : 0) !== m) failures++;
    }
    results.push({ maxErr, rate: failures / trials });
  }
  return results;
}

export function formatHex(bytes: Uint8Array | null): string {
  if (!bytes) return '--';
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexPreview(bytes: Uint8Array, shown = 64): string {
  const fullHex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${fullHex.slice(0, shown * 2)}... [${bytes.length - shown} more bytes]`;
}

export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

export function renderCtDiff(pre: Uint8Array | null, post: Uint8Array | null, maxBytes = 64): string {
  if (!pre || !post) return '';
  const commonLength = Math.min(pre.length, post.length);
  const firstDifference = Array.from({ length: commonLength }, (_, i) => i)
    .find((i) => pre[i] !== post[i]);
  const start = firstDifference !== undefined && firstDifference >= maxBytes
    ? Math.max(0, Math.min(firstDifference - Math.floor(maxBytes / 2), commonLength - maxBytes))
    : 0;
  const parts: string[] = [];
  const end = Math.min(commonLength, start + maxBytes);
  if (start > 0) parts.push(`... [bytes 0–${start - 1}] `);
  for (let i = start; i < end; i++) {
    const hex = post[i].toString(16).padStart(2, '0');
    if (pre[i] !== post[i]) {
      parts.push(`<span class="tampered">${hex}</span>`);
    } else {
      parts.push(hex);
    }
  }
  if (post.length > end) parts.push(` ... [${post.length - end} more]`);
  return parts.join('');
}
