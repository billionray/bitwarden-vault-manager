import test from 'node:test';
import assert from 'node:assert/strict';
import { encryptString, decryptToString } from '../src/crypto.js';
const keys = () => ({ encKey: crypto.getRandomValues(new Uint8Array(32)), macKey: crypto.getRandomValues(new Uint8Array(32)) });
test('authenticated ciphertext requires a valid MAC and known encryption type', async () => {
  const key = keys(), ciphertext = await encryptString('sample', key);
  assert.equal(await decryptToString(ciphertext, key), 'sample');
  await assert.rejects(decryptToString(ciphertext.split('|').slice(0, 2).join('|'), key));
  await assert.rejects(decryptToString(ciphertext.replace(/^2/, '9'), key));
  await assert.rejects(decryptToString(ciphertext, keys()), /HMAC/);
});
