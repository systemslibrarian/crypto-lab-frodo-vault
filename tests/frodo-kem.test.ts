import { describe, it, expect } from 'vitest';
import { getFrodoKem, getMlKem768, bytesEqual, medianMs } from '../src/frodo-kem';

describe('bytesEqual', () => {
  it('is true for identical arrays', () => {
    expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });

  it('is false for differing length or content', () => {
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
    expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
  });
});

describe('medianMs', () => {
  it('returns a non-negative number and runs fn the requested times', () => {
    let calls = 0;
    const m = medianMs(() => {
      calls += 1;
    }, 5);
    expect(calls).toBe(5);
    expect(m).toBeGreaterThanOrEqual(0);
  });
});

// These exercise the REAL liboqs WASM engine (eFrodoKEM / ML-KEM-768).
describe('real FrodoKEM round-trip (eFrodoKEM-640-AES)', () => {
  it('produces spec-accurate sizes and matching shared secrets', async () => {
    const kem = await getFrodoKem('frodo640');
    const { publicKey, secretKey } = kem.generateKeyPair();
    expect(publicKey.length).toBe(9616);
    expect(secretKey.length).toBe(19888);

    const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
    expect(ciphertext.length).toBe(9720);
    expect(sharedSecret.length).toBe(16);

    const recovered = kem.decapsulate(ciphertext, secretKey);
    expect(bytesEqual(sharedSecret, recovered)).toBe(true);
  });

  it('rejects a tampered ciphertext (implicit rejection → different secret)', async () => {
    const kem = await getFrodoKem('frodo640');
    const { publicKey, secretKey } = kem.generateKeyPair();
    const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);

    const tampered = Uint8Array.from(ciphertext);
    tampered[0] ^= 0x01;
    const recovered = kem.decapsulate(tampered, secretKey);
    expect(bytesEqual(sharedSecret, recovered)).toBe(false);
  });
});

describe('real ML-KEM-768 round-trip (for the hybrid exhibit)', () => {
  it('round-trips with a 32-byte shared secret', async () => {
    const kem = await getMlKem768();
    const { publicKey, secretKey } = kem.generateKeyPair();
    expect(publicKey.length).toBe(1184);

    const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
    expect(sharedSecret.length).toBe(32);

    const recovered = kem.decapsulate(ciphertext, secretKey);
    expect(bytesEqual(sharedSecret, recovered)).toBe(true);
  });
});
