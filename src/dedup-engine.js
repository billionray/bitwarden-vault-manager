/**
 * Dedup Engine — Fusion Strategy
 * Analyzes decrypted vault items to find duplicates and orphans
 * Supports 3 scenarios: pure delete, complementary merge, deep merge
 */
import { t } from './i18n.js';

/**
 * Analyze ciphers and return duplicate groups + orphans
 * @param {Array} ciphers - Array of decrypted cipher objects
 * @returns {{ duplicateGroups: Array, orphans: Array, stats: Object }}
 */
export function analyzeCiphers(ciphers) {
  // Only analyze login type (type=1)
  const logins = ciphers.filter(c => c.type === 1 && !c.decrypted?.error);
  const others = ciphers.filter(c => c.type !== 1);

  const exactDupes = findExactDuplicates(logins);
  const sameSiteDupes = findSameSiteDuplicates(logins, exactDupes);
  const allDupeGroups = [...exactDupes, ...sameSiteDupes];
  const orphans = findOrphans(logins, allDupeGroups);

  const totalDuplicateItems = exactDupes.reduce((sum, g) => sum + g.items.length - 1, 0)
    + sameSiteDupes.reduce((sum, g) => sum + g.items.length - 1, 0);

  return {
    duplicateGroups: allDupeGroups,
    orphans,
    stats: {
      totalItems: ciphers.length,
      loginItems: logins.length,
      otherItems: others.length,
      exactDuplicateGroups: exactDupes.length,
      sameSiteDuplicateGroups: sameSiteDupes.length,
      totalDuplicateItems,
      orphanItems: orphans.length,
      noFolderItems: ciphers.filter(c => !c.raw?.FolderId && !c.raw?.folderId).length,
    },
  };
}

// ========================
// DEEP IDENTITY COMPARISON
// ========================

/**
 * Find specific differences between two items
 * Returns array of diff labels for UI display
 */
function findDiffFields(a, b) {
  const da = a.decrypted || {};
  const db = b.decrypted || {};
  const diffs = [];

  if ((da.username || '') !== (db.username || '')) diffs.push(t('detail.username'));
  if ((da.password || '') !== (db.password || '')) diffs.push(t('detail.password'));
  if (JSON.stringify(da.passwordHistory || []) !== JSON.stringify(db.passwordHistory || [])) diffs.push(t('detail.password.history'));
  if ((a.raw?.FolderId || a.raw?.folderId || null) !== (b.raw?.FolderId || b.raw?.folderId || null)) diffs.push('Folder');
  const matches = item => (item.raw?.Login?.Uris || item.raw?.login?.uris || []).map(u => u.Match ?? u.match ?? null);
  if (JSON.stringify(matches(a)) !== JSON.stringify(matches(b))) diffs.push('URI match');

  // Name
  if (da.name !== db.name) diffs.push(t('dup.title.warn'));

  // TOTP
  if (da.totp !== db.totp) diffs.push('TOTP');

  // Notes
  if ((da.notes || '') !== (db.notes || '')) diffs.push(t('detail.notes'));

  // URIs
  const urisA = new Set((da.uris || []).filter(Boolean));
  const urisB = new Set((db.uris || []).filter(Boolean));
  if (!setsEqual(urisA, urisB)) diffs.push('URI');

  // Custom fields
  if (serializeFields(da.fields) !== serializeFields(db.fields)) diffs.push(t('detail.section.fields'));

  // Passkeys
  const passkeysA = new Set(getPasskeyIds(a));
  const passkeysB = new Set(getPasskeyIds(b));
  if (!setsEqual(passkeysA, passkeysB)) diffs.push(t('detail.passkey'));

  // Favorite
  const favA = a.raw?.Favorite || a.raw?.favorite || false;
  const favB = b.raw?.Favorite || b.raw?.favorite || false;
  if (favA !== favB) diffs.push(t('detail.favorite'));

  // Reprompt
  if ((da.reprompt || 0) !== (db.reprompt || 0)) diffs.push(t('detail.reprompt'));

  return diffs;
}

/**
 * Analyze all pairwise differences in a group and return the union of diffs
 */
function analyzeGroupDiffs(items) {
  if (items.length < 2) return { pureDelete: true, diffFields: [] };

  const allDiffs = new Set();
  const base = items[0];
  for (let i = 1; i < items.length; i++) {
    const diffs = findDiffFields(base, items[i]);
    diffs.forEach(d => allDiffs.add(d));
  }

  return {
    pureDelete: allDiffs.size === 0,
    diffFields: [...allDiffs],
  };
}

// ========================
// DUPLICATE FINDING
// ========================

/**
 * Find exact duplicates: same URI + same username + same password
 * Now also marks pureDelete vs needsMerge based on deep comparison
 */
function findExactDuplicates(logins) {
  const groups = new Map();

  for (const login of logins) {
    const uri = getPrimaryUri(login);
    const username = login.decrypted?.username || '';
    const password = login.decrypted?.password || '';
    const key = JSON.stringify([normalizeUri(uri), username, password]);

    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(login);
  }

  return Array.from(groups.values())
    .filter(g => g.length > 1)
    .map(items => {
      const sorted = sortByQuality(items);
      const { pureDelete, diffFields } = analyzeGroupDiffs(sorted);
      return {
        type: 'exact',
        label: `${t('dup.exact')}: ${sorted[0].decrypted?.name || getPrimaryUri(sorted[0])}`,
        matchKey: getPrimaryUri(sorted[0]),
        items: sorted,
        autoMergeable: true,
        pureDelete,
        needsMerge: !pureDelete,
        diffFields,
      };
    });
}

/**
 * Find same-site duplicates: same URI but different credentials
 * Excludes items already captured in exact duplicates
 */
function findSameSiteDuplicates(logins, exactDupes) {
  // Collect IDs already in exact duplicate groups
  const exactIds = new Set();
  for (const group of exactDupes) {
    for (const item of group.items) {
      exactIds.add(item.id);
    }
  }

  const groups = new Map();
  for (const login of logins) {
    const uri = normalizeUri(getPrimaryUri(login));
    if (!uri) continue;

    if (!groups.has(uri)) groups.set(uri, []);
    groups.get(uri).push(login);
  }

  return Array.from(groups.values())
    .filter(g => g.length > 1)
    // Only include groups where not ALL items are exact duplicates of each other
    .filter(g => {
      const nonExactCount = g.filter(i => !exactIds.has(i.id)).length;
      return nonExactCount > 0 || g.length > 1;
    })
    // Skip groups that are entirely covered by exact duplicate groups
    .filter(g => !g.every(i => exactIds.has(i.id)))
    .map(items => {
      const sorted = sortByQuality(items);
      const { pureDelete, diffFields } = analyzeGroupDiffs(sorted);
      return {
        type: 'same_site',
        label: `${t('dup.samesite')}: ${normalizeUri(getPrimaryUri(sorted[0]))}`,
        matchKey: normalizeUri(getPrimaryUri(sorted[0])),
        items: sorted,
        autoMergeable: false,
        pureDelete,
        needsMerge: !pureDelete,
        diffFields,
      };
    });
}

/**
 * Find orphan items: login items that appear in NO duplicate group
 * These are truly standalone entries with no duplicates anywhere
 */
function findOrphans(logins, allDupeGroups) {
  const dupeIds = new Set();
  for (const group of allDupeGroups) {
    for (const item of group.items) {
      dupeIds.add(item.id);
    }
  }
  return logins.filter(c => !dupeIds.has(c.id));
}

/**
 * Sort items by quality - best item first (the one to keep)
 * Priority: has passkeys > has TOTP > has custom fields > has notes > newest
 */
function sortByQuality(items) {
  return [...items].sort((a, b) => {
    // Has Fido2 credentials (passkeys)
    const aPasskeys = a.raw?.Login?.Fido2Credentials?.length || 0;
    const bPasskeys = b.raw?.Login?.Fido2Credentials?.length || 0;
    if (aPasskeys !== bPasskeys) return bPasskeys - aPasskeys;

    // Has TOTP
    const aTotp = a.decrypted?.totp ? 1 : 0;
    const bTotp = b.decrypted?.totp ? 1 : 0;
    if (aTotp !== bTotp) return bTotp - aTotp;

    // Has custom fields
    const aFields = a.decrypted?.fields?.length || 0;
    const bFields = b.decrypted?.fields?.length || 0;
    if (aFields !== bFields) return bFields - aFields;

    // Has notes
    const aNotes = a.decrypted?.notes?.length || 0;
    const bNotes = b.decrypted?.notes?.length || 0;
    if (aNotes !== bNotes) return bNotes - aNotes;

    // Newest revision date
    const aDate = new Date(a.raw?.RevisionDate || 0).getTime();
    const bDate = new Date(b.raw?.RevisionDate || 0).getTime();
    return bDate - aDate;
  });
}

// ========================
// MERGE OPERATIONS (Fusion Strategy)
// ========================

/**
 * Build merge operations from selected groups
 * Merge decrypted fields; the payload builder encrypts using the destination key.
 * Returns { toCreate: [...], toDelete: [...], errors: [...] }
 *
 * toCreate has two formats:
 *   1. Normal (isPasskeyMerge=false): decrypted plaintext fields
 *   2. Passkey (isPasskeyMerge=true): plaintext fields + retained key/passkey data
 *      Execution layer converts to Create-Then-Delete (same as single-item edit save)
 */
export function buildMergeOperations(selectedGroups) {
  const toCreate = [], toDelete = [], errors = [], pureDeleteGroups = [];
  const handled = new Set();
  for (const group of selectedGroups) {
    const items = group.items;
    const fail = reason => errors.push({ groupLabel: group.label, reason });
    if (items.length < 2) continue;
    if (items.some(i => handled.has(i.id))) { fail(t('merge.overlap')); continue; }
    if (items.some(i => !i.decrypted || i.decrypted.error)) { fail(t('merge.decrypt.failed')); continue; }
    const original = i => i.raw?._original || i.raw || {};
    if (items.some(i => {
      const raw = original(i);
      return raw.OrganizationId || raw.organizationId || (raw.Attachments || raw.attachments || []).length;
    })) { fail(t('merge.unsupported.metadata')); continue; }
    const values = field => [...new Set(items.map(i => i.decrypted[field] || '').filter(Boolean))];
    if (['username', 'password', 'totp'].some(field => values(field).length > 1)) {
      fail(t('merge.credentials.conflict')); continue;
    }
    const passkeyItems = items.filter(i => getPasskeyCredentials(i).length > 0);
    // Never discard another item's passkeys. Encrypted IDs cannot be compared across keys.
    if (passkeyItems.length > 1) { fail(t('merge.multiple.passkeys')); continue; }
    const keepItem = passkeyItems[0] || group.keepItem || items[0];
    if (!items.includes(keepItem)) { fail(t('merge.decrypt.failed')); continue; }
    if (items.some(i => {
      const raw = original(i);
      return (raw.PasswordHistory || raw.passwordHistory || []).length && !i.decrypted.passwordHistory;
    })) { fail(t('merge.decrypt.failed')); continue; }
    const pureDelete = analyzeGroupDiffs(items).pureDelete;
    if (pureDelete) {
      pureDeleteGroups.push(items.filter(i => i.id !== keepItem.id).map(i => i.id));
      for (const item of items) if (item.id !== keepItem.id) toDelete.push(item.id);
    } else {
      const { chosen, discarded } = chooseBestTitle([...new Set(items.map(i => i.decrypted.name || '').filter(Boolean))]);
      const notes = [...new Set(items.map(i => i.decrypted.notes || '').filter(Boolean))];
      if (discarded.length) notes.push('合并前的其他标题: ' + discarded.join(', '));
      const fields = [], uris = [], passwordHistory = [];
      const seenFields = new Set(), seenUris = new Set(), seenHistory = new Set();
      for (const item of items) {
        for (const field of item.decrypted.fields || []) {
          const key = JSON.stringify([field.name, field.value, field.type, field.linkedId]);
          if (!seenFields.has(key)) { seenFields.add(key); fields.push({ ...field }); }
        }
        const rawLogin = item.raw?.Login || item.raw?.login || {};
        (item.decrypted.uris || []).forEach((uri, index) => {
          if (!uri) return;
          const rawUri = (rawLogin.Uris || rawLogin.uris || [])[index];
          const match = rawUri?.Match ?? rawUri?.match ?? null;
          const key = JSON.stringify([uri, match]);
          if (!seenUris.has(key)) { seenUris.add(key); uris.push({ uri, match }); }
        });
        for (const history of item.decrypted.passwordHistory || []) {
          const key = JSON.stringify([history.password, history.lastUsedDate]);
          if (!seenHistory.has(key)) { seenHistory.add(key); passwordHistory.push({ ...history }); }
        }
      }
      const raw = original(keepItem);
      const login = raw.Login || raw.login || {};
      toCreate.push({
        groupLabel: group.label, type: 1, name: chosen, notes: notes.join('\n\n') || null,
        username: values('username')[0] || '', password: values('password')[0] || '', totp: values('totp')[0] || null,
        uris, fields, passwordHistory,
        folderId: keepItem.raw?.FolderId || keepItem.raw?.folderId || null,
        favorite: items.some(i => i.raw?.Favorite || i.raw?.favorite),
        reprompt: items.some(i => (i.raw?.Reprompt ?? i.raw?.reprompt ?? 0) === 1) ? 1 : 0,
        passwordRevisionDate: login.PasswordRevisionDate ?? login.passwordRevisionDate ?? keepItem.decrypted.passwordRevisionDate ?? null,
        autofillOnPageLoad: login.AutofillOnPageLoad ?? login.autofillOnPageLoad ?? null,
        isPasskeyMerge: passkeyItems.length > 0,
        cipherKey: raw.Key || raw.key || keepItem.raw?.Key || null,
        fido2Credentials: login.Fido2Credentials || login.fido2Credentials || [],
      });
      toDelete.push(...items.map(i => i.id));
    }
    items.forEach(i => handled.add(i.id));
  }
  return { toCreate, toDelete, errors, pureDeleteGroups };
}

/**
 * Choose the best title from a list of unique titles
 * Rules:
 *   1. Same titles → no change needed (handled by caller)
 *   2. Chinese title + English title → keep Chinese, discard English
 *   3. Two English titles → keep shorter one, discard longer
 * @returns {{ chosen: string, discarded: string[] }}
 */
function chooseBestTitle(titles) {
  if (titles.length === 0) return { chosen: t('item.untitled'), discarded: [] };
  if (titles.length === 1) return { chosen: titles[0], discarded: [] };

  // Classify each title
  const classified = titles.map(t => ({
    title: t,
    hasChinese: /[\u4e00-\u9fff\u3400-\u4dbf]/.test(t),
  }));

  const chinese = classified.filter(c => c.hasChinese);
  const nonChinese = classified.filter(c => !c.hasChinese);

  let chosen;
  let discarded;

  if (chinese.length > 0) {
    // Prefer Chinese title; if multiple, pick the shortest
    chinese.sort((a, b) => a.title.length - b.title.length);
    chosen = chinese[0].title;
    discarded = titles.filter(t => t !== chosen);
  } else {
    // All non-Chinese: pick the shortest
    nonChinese.sort((a, b) => a.title.length - b.title.length);
    chosen = nonChinese[0].title;
    discarded = titles.filter(t => t !== chosen);
  }

  return { chosen, discarded };
}

// ========================
// HELPERS
// ========================

function getPrimaryUri(cipher) {
  if (cipher.decrypted?.uris && cipher.decrypted.uris.length > 0) {
    return cipher.decrypted.uris[0] || '';
  }
  return '';
}

/**
 * Known multi-part TLDs (eTLD list subset).
 * For hostnames ending in these, the registered domain is the part before + the TLD.
 * e.g., "shop.example.co.uk" → "example.co.uk"
 */
const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'co.kr', 'or.kr', 'ne.kr',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'com.tw', 'org.tw', 'net.tw', 'edu.tw',
  'com.hk', 'org.hk', 'net.hk', 'edu.hk', 'gov.hk',
  'co.nz', 'net.nz', 'org.nz',
  'com.br', 'org.br', 'net.br',
  'com.mx', 'org.mx', 'net.mx',
  'co.in', 'net.in', 'org.in',
  'com.sg', 'org.sg', 'net.sg', 'edu.sg', 'gov.sg',
  'co.za', 'org.za', 'net.za',
  'co.il', 'org.il', 'net.il',
  'com.tr', 'org.tr', 'net.tr',
  'co.th', 'or.th', 'ac.th',
  'com.vn', 'net.vn', 'org.vn',
  'com.ar', 'org.ar', 'net.ar',
]);

/**
 * Extract registered domain (eTLD+1) from a hostname.
 * "pan.baidu.com" → "baidu.com"
 * "shop.example.co.uk" → "example.co.uk"
 * "baidu.com" → "baidu.com"  (already a base domain)
 */
function getRegisteredDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname; // already base domain or single-label

  // Check if the last two parts form a known multi-part TLD
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(lastTwo)) {
    // Need 3 parts: "example.co.uk"
    return parts.slice(-3).join('.');
  }

  // Standard TLD: take last 2 parts ("baidu.com")
  return parts.slice(-2).join('.');
}

function normalizeUri(uri) {
  if (!uri) return '';
  try {
    // Handle mobile app URIs: androidapp://com.example.app, iosapp://com.example.app
    const appMatch = uri.match(/^(androidapp|iosapp):\/\/(.+)/i);
    if (appMatch) {
      return appMatch[2].toLowerCase().split('/')[0].trim();
    }
    const u = new URL(uri.startsWith('http') ? uri : `https://${uri}`);
    return getRegisteredDomain(u.hostname.toLowerCase());
  } catch {
    return uri.toLowerCase().trim();
  }
}

function serializeFields(fields) {
  if (!fields || fields.length === 0) return '';
  return fields
    .map(f => JSON.stringify([f.name || '', f.value || '', f.type ?? 0, f.linkedId ?? null]))
    .sort()
    .join('||');
}

function getPasskeyCredentials(cipher) {
  return cipher.raw?.Login?.Fido2Credentials || cipher.raw?.login?.fido2Credentials || cipher.raw?._original?.Login?.Fido2Credentials || cipher.raw?._original?.login?.fido2Credentials || [];
}

function getPasskeyIds(cipher) {
  return getPasskeyCredentials(cipher).map(p => p.CredentialId || p.credentialId || '').filter(Boolean);
}

function setsEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const v of a) {
    if (!b.has(v)) return false;
  }
  return true;
}
