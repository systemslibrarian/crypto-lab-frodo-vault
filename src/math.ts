// FrodoKEM-640 parameters: n=640, confirmed spec-accurate
// FrodoKEM-976 parameters: n=976, confirmed spec-accurate
// FrodoKEM-1344 parameters: n=1344, confirmed spec-accurate
//
// All three parameter sets below match the FrodoKEM specification exactly:
//   FrodoKEM-640:  n=640,  q=2^15, pk=9616B,  sk=19888B, ct=9720B,  σ=2.8, maxError=12
//   FrodoKEM-976:  n=976,  q=2^16, pk=15632B, sk=31296B, ct=15744B, σ=2.3, maxError=10
//   FrodoKEM-1344: n=1344, q=2^16, pk=21520B, sk=43088B, ct=21632B, σ=1.4, maxError=6
// Toy LWE (n=3, q=97) and decryption-failure demo (q=17) exist in separate
// functions (buildToyLweSamples, computeFailureProbabilities) for pedagogy only
// and are intentionally not full parameter sets.

export type LweSample = {
  a: [number, number, number];
  b: number;
  e: number;
};

export type FrodoId = 'frodo640' | 'frodo976' | 'frodo1344';

export type FrodoParams = {
  id: FrodoId;
  label: string;
  n: number;
  q: number;
  classicalBits: number;
  pqBits: number;
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
    classicalBits: 128,
    pqBits: 103,
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
    classicalBits: 192,
    pqBits: 150,
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
    classicalBits: 256,
    pqBits: 207,
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
  const parts: string[] = [];
  const len = Math.min(pre.length, post.length, maxBytes);
  for (let i = 0; i < len; i++) {
    const hex = post[i].toString(16).padStart(2, '0');
    if (pre[i] !== post[i]) {
      parts.push(`<span class="tampered">${hex}</span>`);
    } else {
      parts.push(hex);
    }
  }
  if (post.length > maxBytes) parts.push(`... [${post.length - maxBytes} more]`);
  return parts.join('');
}
