import { encryptString, decryptSymmetricKey } from './crypto.js';
import { t } from './i18n.js';

export async function buildCipherCreatePayload(op, isDemoMode, symKey) {
  const enc = async (val) => {
    if (!val) return null;
    return isDemoMode ? val : await encryptString(val, symKey);
  };

  const payload = {
    type: op.type ?? 1,
    organizationId: null,
    folderId: op.folderId || null,
    name: await enc(op.name || t('item.untitled')),
    notes: await enc(op.notes),
    favorite: op.favorite || false,
    reprompt: op.reprompt ?? 0,
  };

  // Login
  if (op.type === 1) {
    const uris = [];
    for (const uri of (op.uris || [])) {
      if (uri) {
        uris.push({
          uri: await enc(typeof uri === 'string' ? uri : uri.uri),
          match: typeof uri === 'string' ? null : uri.match,
        });
      }
    }
    payload.login = {
      passwordRevisionDate: op.passwordRevisionDate,
      autofillOnPageLoad: op.autofillOnPageLoad,
      username: await enc(op.username),
      password: await enc(op.password),
      totp: await enc(op.totp),
      uris,
    };
  }

  // Custom fields
  if (op.fields && op.fields.length > 0) {
    payload.fields = [];
    for (const f of op.fields) {
      payload.fields.push({
        name: await enc(f.name),
        value: await enc(f.value),
        type: f.type ?? 0,
        linkedId: f.linkedId ?? null,
      });
    }
  }

  // Re-encrypt plaintext history with the destination key.
  if (op.passwordHistory && op.passwordHistory.length > 0) {
    payload.passwordHistory = await Promise.all(op.passwordHistory.map(async h => ({
      password: await enc(h.password),
      lastUsedDate: h.lastUsedDate,
    })));
  }

  return payload;
}

/** Build all merged fields with the retained passkey's encryption key. */
export async function buildPasskeyMergePayload(op, isDemoMode, symKey) {
  const key = !isDemoMode && op.cipherKey ? await decryptSymmetricKey(op.cipherKey, symKey) : symKey;
  const payload = await buildCipherCreatePayload(op, isDemoMode, key);
  if (op.cipherKey) payload.key = op.cipherKey;
  payload.login.fido2Credentials = op.fido2Credentials.map(credential =>
    Object.fromEntries(Object.entries(credential).map(([name, value]) => [name[0].toLowerCase() + name.slice(1), value]))
  );
  return payload;
}
