const ITERATIONS = 600000;
const encoder = new TextEncoder();

const toBase64 = bytes => btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''));
const fromBase64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));

async function deriveKey(password, salt) {
  if (typeof password !== 'string' || !password) throw new Error('A file password is required');
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

export async function encryptCredentials(data, password) {
  if (typeof password !== 'string' || password.length < 12) throw new Error('Use at least 12 characters for the file password');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(JSON.stringify(data)));
  return JSON.stringify({ version: 2, salt: toBase64(salt), iv: toBase64(iv), data: toBase64(new Uint8Array(encrypted)) });
}

export async function decryptCredentials(buffer, password) {
  let file;
  try { file = JSON.parse(new TextDecoder().decode(buffer)); } catch { throw new Error('legacy_credential_file'); }
  if (file?.version !== 2) throw new Error('legacy_credential_file');
  if (![file.salt, file.iv, file.data].every(v => typeof v === 'string')) throw new Error('Invalid credential file');
  const salt = fromBase64(file.salt), iv = fromBase64(file.iv), data = fromBase64(file.data);
  if (salt.length !== 16 || iv.length !== 12 || data.length < 16) throw new Error('Invalid credential file');
  const key = await deriveKey(password, salt);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return JSON.parse(new TextDecoder().decode(plain));
}
