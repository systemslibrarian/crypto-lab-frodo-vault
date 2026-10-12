// eFrodoKEM policy: fewer than 256 ciphertexts per public key (draft -03).
export const MAX_CIPHERTEXTS = 255;
const uses = new WeakMap<Uint8Array, number>();
export function ciphertextCount(key: Uint8Array): number { return uses.get(key) ?? 0; }
export function limitedEncapsulation<T>(key: Uint8Array, encapsulate: () => T): T {
  const count = ciphertextCount(key);
  if (count >= MAX_CIPHERTEXTS) throw new Error('eFrodoKEM key exhausted: generate a new keypair before ciphertext 256.');
  const result = encapsulate();
  uses.set(key, count + 1);
  return result;
}
export const REUSABLE_PARAMETERS = {
  frodo640: { saltBytes: 32, seedSEBytes: 32, ephemeralSeedSEBytes: 16 },
  frodo976: { saltBytes: 48, seedSEBytes: 48, ephemeralSeedSEBytes: 24 },
  frodo1344: { saltBytes: 64, seedSEBytes: 64, ephemeralSeedSEBytes: 32 },
} as const;
