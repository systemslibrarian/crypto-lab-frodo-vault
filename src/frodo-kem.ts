// ============================================================================
// Real FrodoKEM engine — thin wrapper over @oqs/liboqs-js (Open Quantum Safe)
// ============================================================================
//
// Exhibits 2–4 (key generation, encapsulation/decapsulation, and the
// comparison/hybrid panel) run GENUINE, vetted post-quantum cryptography here:
// FrodoKEM compiled to WebAssembly from liboqs, plus ML-KEM-768 for the hybrid.
// This replaces the former SHA-256 stand-in — shared secrets now match because
// the LWE math says so, and a tampered ciphertext fails decapsulation for real
// (FrodoKEM's implicit rejection returns an unrelated secret).
//
// We use the eFrodoKEM-*-AES ("ephemeral FrodoKEM") variants because their key
// and ciphertext sizes match the figures the rest of the demo displays exactly:
//   640:  pk 9616   sk 19888   ct 9720    ss 16
//   976:  pk 15632  sk 31296   ct 15744   ss 24
//   1344: pk 21520  sk 43088   ct 21632   ss 32
// The salted FrodoKEM-* variants are otherwise identical but add 32 bytes of
// salt to each ciphertext (9752 / 15792 / 21696), which would not match the
// displayed tables. liboqs is production-grade, but this UI is still a learning
// tool: keys live only in memory and are never persisted or reused.
// ============================================================================

import {
  createEFrodoKEM640AES,
  createEFrodoKEM976AES,
  createEFrodoKEM1344AES,
  createMLKEM768,
} from '@oqs/liboqs-js';
import type { FrodoId } from './math';

// Minimal structural type shared by every liboqs KEM instance. We avoid naming
// the library's per-algorithm class types so all three Frodo levels and ML-KEM
// flow through one interface.
export interface KemInstance {
  generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate(publicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array };
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
}

type Factory = () => Promise<KemInstance>;

const FRODO_FACTORY: Record<FrodoId, Factory> = {
  frodo640: createEFrodoKEM640AES,
  frodo976: createEFrodoKEM976AES,
  frodo1344: createEFrodoKEM1344AES,
};

// WASM instantiation is the slow part (tens of ms + a one-time module download).
// Each instance is stateless across keygen/encaps/decaps, so we cache one per
// algorithm for the page lifetime and reuse it.
const cache = new Map<string, Promise<KemInstance>>();

export function getFrodoKem(id: FrodoId): Promise<KemInstance> {
  let inst = cache.get(id);
  if (!inst) {
    inst = FRODO_FACTORY[id]();
    cache.set(id, inst);
  }
  return inst;
}

export function getMlKem768(): Promise<KemInstance> {
  let inst = cache.get('mlkem768');
  if (!inst) {
    inst = createMLKEM768();
    cache.set('mlkem768', inst);
  }
  return inst;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// Median wall-clock (ms) of `fn` over `runs` iterations — median (not mean)
// shrugs off GC/scheduler spikes.
export function medianMs(fn: () => void, runs: number): number {
  return statsMs(fn, runs).median;
}

// Median + min/max wall-clock (ms) of `fn`, after discarding `warmup` untimed
// iterations so the JIT has settled — the measurement behind Exhibit 4's
// benchmark. Reports the range so learners can see the variance, not just a point.
export function statsMs(
  fn: () => void,
  samples: number,
  warmup = 0,
): { median: number; min: number; max: number } {
  for (let i = 0; i < warmup; i += 1) fn();
  const xs: number[] = [];
  for (let i = 0; i < samples; i += 1) {
    const t = performance.now();
    fn();
    xs.push(performance.now() - t);
  }
  xs.sort((a, b) => a - b);
  return { median: xs[Math.floor(xs.length / 2)], min: xs[0], max: xs[xs.length - 1] };
}
