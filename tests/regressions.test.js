import test from 'node:test';
import assert from 'node:assert/strict';
import { encryptString, decryptToString } from '../src/crypto.js';
import { analyzeCiphers, buildMergeOperations } from '../src/dedup-engine.js';
import { buildCipherCreatePayload, buildPasskeyMergePayload } from '../src/merge-payload.js';

const keys = () => ({ encKey: crypto.getRandomValues(new Uint8Array(32)), macKey: crypto.getRandomValues(new Uint8Array(32)) });
const item = (id, changes = {}) => ({ id, type: 1, raw: { Login: { Uris: [{ Match: 0 }] } }, decrypted: { name: 'Example', username: 'user', password: 'password', uris: ['https://login.example.org:8443/account'], ...changes } });
const plan = (items, extra = {}) => buildMergeOperations([{ label: 'test', items, keepItem: items[0], ...extra }]);

test('authenticated ciphertext requires a valid MAC and known encryption type', async () => {
  const key = keys(), ciphertext = await encryptString('sample', key);
  assert.equal(await decryptToString(ciphertext, key), 'sample');
  await assert.rejects(decryptToString(ciphertext.split('|').slice(0, 2).join('|'), key));
  await assert.rejects(decryptToString(ciphertext.replace(/^2/, '9'), key));
  await assert.rejects(decryptToString(ciphertext, keys()), /HMAC/);
});

test('different credentials cannot become pure deletion even with stale UI flags', () => {
  for (const field of ['username', 'password', 'totp']) {
    const items = [item('a', { [field]: 'one' }), item('b', { [field]: 'two' })];
    assert.equal(analyzeCiphers(items).duplicateGroups[0].pureDelete, false);
    const ops = plan(items, { pureDelete: true });
    assert.equal(ops.toCreate.length, 0); assert.equal(ops.toDelete.length, 0); assert.equal(ops.errors.length, 1);
  }
  assert.deepEqual(plan([item('a'), item('b')]).toDelete, ['b']);
});

test('merge preserves notes, full URI/match rules, conflicting field values and history', async () => {
  const a = item('a', { notes: 'first note', fields: [{ name: 'n', value: 'one', type: 0 }], passwordHistory: [{ password: 'old', lastUsedDate: '2020-01-01' }] });
  const b = item('b', { notes: 'second note', fields: [{ name: 'n', value: 'two', type: 0 }] });
  const ops = plan([a, b]), key = keys(), payload = await buildCipherCreatePayload(ops.toCreate[0], false, key);
  assert.equal(await decryptToString(payload.notes, key), 'first note\n\nsecond note');
  assert.equal(await decryptToString(payload.login.uris[0].uri, key), a.decrypted.uris[0]);
  assert.equal(payload.login.uris[0].match, 0); assert.equal(payload.fields.length, 2);
  assert.equal(await decryptToString(payload.passwordHistory[0].password, key), 'old');
});

test('passkey merge re-encrypts donor fields under retained key and fails closed for invalid key', async () => {
  const userKey = keys(), retainedKey = keys();
  // Encode the binary 64-byte symmetric key using the same AES-CBC/HMAC format.
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const aes = await crypto.subtle.importKey('raw', userKey.encKey, 'AES-CBC', false, ['encrypt']);
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aes, new Uint8Array([...retainedKey.encKey, ...retainedKey.macKey])));
  const hmac = await crypto.subtle.importKey('raw', userKey.macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hmac, new Uint8Array([...iv, ...data])));
  const b64 = bytes => Buffer.from(bytes).toString('base64');
  const protectedKey = `2.${b64(iv)}|${b64(data)}|${b64(mac)}`;
  const a = item('a', { password: '' }), b = item('b', { notes: 'donor note' });
  const credentials = [{ credentialId: await encryptString('credential', retainedKey), keyValue: await encryptString('private key', retainedKey) }];
  a.raw.Key = protectedKey;
  a.raw._original = { key: protectedKey, login: { fido2Credentials: credentials, autofillOnPageLoad: false, passwordRevisionDate: "2020-01-01" } };
  const ops = plan([a, b]);
  assert.equal(ops.errors.length, 0);
  const payload = await buildPasskeyMergePayload(ops.toCreate[0], false, userKey);
  assert.equal(await decryptToString(payload.login.password, retainedKey), 'password');
  assert.equal(await decryptToString(payload.notes, retainedKey), 'donor note');
  assert.deepEqual(payload.login.fido2Credentials, credentials);
  assert.equal(payload.login.autofillOnPageLoad, false);
  assert.equal(payload.login.passwordRevisionDate, "2020-01-01");
  await assert.rejects(decryptToString(payload.login.password, userKey));
  await assert.rejects(buildPasskeyMergePayload({ ...ops.toCreate[0], cipherKey: 'invalid' }, false, userKey));
});

test('unsafe or overlapping merge groups never schedule duplicate deletions', () => {
  for (const mutate of [i => { i.decrypted.error = 'failed'; }, i => { i.raw._original = { attachments: [{}] }; }, i => { i.raw.OrganizationId = 'org'; }, i => { i.raw.PasswordHistory = [{}]; }]) {
    const a = item('a'), b = item('b'); mutate(b);
    assert.equal(plan([a, b]).toDelete.length, 0);
  }
  const a = item('a'), b = item('b'), c = item('c');
  const ops = buildMergeOperations([{ label: 'one', items: [a, b], keepItem: a }, { label: 'two', items: [b, c], keepItem: b }]);
  assert.deepEqual(ops.toDelete, ['b']); assert.equal(ops.errors.length, 1);
  for (const i of [a, b]) i.raw.Login.Fido2Credentials = [{ CredentialId: 'credential' }];
  assert.equal(plan([a, b]).toDelete.length, 0);
});
