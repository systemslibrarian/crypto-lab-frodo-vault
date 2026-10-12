import { describe, it, expect } from 'vitest';
import { limitedEncapsulation, ciphertextCount, REUSABLE_PARAMETERS } from '../src/key-use';
describe('eFrodoKEM ciphertext policy used by the Encaps action', () => {
 it('allows 255 actual creations and refuses 256 without calling the engine', () => {
  const key=new Uint8Array([1]); let calls=0;
  for(let i=0;i<255;i++) limitedEncapsulation(key,()=>++calls);
  expect(ciphertextCount(key)).toBe(255);
  expect(()=>limitedEncapsulation(key,()=>++calls)).toThrow(/256/);
  expect(calls).toBe(255);
  const regenerated=new Uint8Array([2]);
  expect(ciphertextCount(regenerated)).toBe(0);
  limitedEncapsulation(regenerated,()=>++calls);
  expect(ciphertextCount(key)).toBe(255);
 });
 it('does not count a failed creation or reset when observed',()=>{
  const key=new Uint8Array([3]);
  expect(()=>limitedEncapsulation(key,()=>{throw Error('failure')})).toThrow();
  expect(ciphertextCount(key)).toBe(0);
  limitedEncapsulation(key,()=>1); limitedEncapsulation(key,()=>2);
  expect(ciphertextCount(key)).toBe(2); expect(ciphertextCount(key)).toBe(2);
 });
 it('distinguishes reusable salt and doubled seedSE per parameter set',()=>{
  expect(Object.values(REUSABLE_PARAMETERS).map(x=>x.saltBytes)).toEqual([32,48,64]);
  for(const p of Object.values(REUSABLE_PARAMETERS)) expect(p.seedSEBytes).toBe(p.ephemeralSeedSEBytes*2);
 });
});
