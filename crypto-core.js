/*
 * Keyform's PassMorph-compatible derivation profile.
 * The UI and brand are independent; the byte-level derivation follows the
 * public PassMorph source so matching inputs/settings reproduce the same output.
 */
export const ITERATIONS = 500_000;
export const KEY_LENGTH_BITS = 256;
export const APP_SALT = new Uint8Array([
  15, 122, 45, 90, 16,
  23, 78, 101, 19, 55,
  11, 22, 33, 44, 55, 66
]);
export const DEFAULT_SETTINGS = Object.freeze({
  length: 24,
  prefix: '$J0$hu@',
  suffix: 'o8o'
});
export const MIN_DERIVED_LENGTH = 1;
const encoder = new TextEncoder();

// Match the source canonicalization exactly: lowercase, trim outer whitespace,
// then remove everything except ASCII letters, digits, and hyphens.
export function canonicalServiceIdentifier(value) {
  return String(value).toLowerCase().trim().replace(/[^a-z0-9-]/g, '');
}

export function requirementsFor(value) {
  return {
    length: value.length >= 10,
    upper: /[A-Z]/.test(value),
    lower: /[a-z]/.test(value),
    number: /[0-9]/.test(value),
    symbol: /[^a-zA-Z0-9]/.test(value)
  };
}

export function validateMaster(value) {
  if (!value) return 'Enter your master key first.';
  if (value.length > 1024) return 'The master key is too long. Use 1,024 characters or fewer.';
  const labels = {
    length: 'at least 10 characters',
    upper: 'an uppercase letter',
    lower: 'a lowercase letter',
    number: 'a number',
    symbol: 'a symbol'
  };
  const failed = Object.entries(requirementsFor(value))
    .filter(([, valid]) => !valid)
    .map(([key]) => labels[key]);
  if (failed.length) {
    return `Your master key must contain ${failed.join(', ').replace(/, ([^,]*)$/, ' and $1')}. This is a basic composition check, not a guarantee of high entropy.`;
  }
  return '';
}

export function validateSettings(candidate) {
  if (!Number.isInteger(candidate.length) || candidate.length < 10 || candidate.length > 40) {
    return 'Choose a total length between 10 and 40 characters.';
  }
  for (const [label, value] of [['Prefix', candidate.prefix], ['Suffix', candidate.suffix]]) {
    if (typeof value !== 'string') return `${label} must be text.`;
    if (/[\u0000-\u001f\u007f]/.test(value)) return `${label} cannot contain control characters.`;
    if (value.length > 30) return `${label} must be 30 characters or fewer.`;
  }
  const affixLength = candidate.prefix.length + candidate.suffix.length;
  if (affixLength > candidate.length) return 'The prefix and suffix are longer than the total password length.';
  if (candidate.length - affixLength < MIN_DERIVED_LENGTH) {
    return 'Leave at least 1 character for the cryptographically derived segment.';
  }
  return '';
}

async function hashServiceIdentifier(canonicalService) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(canonicalService)));
}

export async function deriveHmacKey(masterPassword, serviceIdentifier) {
  const canonicalService = canonicalServiceIdentifier(serviceIdentifier);
  const serviceHash = await hashServiceIdentifier(canonicalService);
  const salt = new Uint8Array(APP_SALT.length + serviceHash.length);
  salt.set(APP_SALT, 0);
  salt.set(serviceHash, APP_SALT.length);

  // Best-effort cleanup: clear the mutable UTF-8 buffer only after Web Crypto
  // has imported it. JavaScript strings and browser-internal copies cannot be
  // reliably zeroized by application code.
  const passwordBytes = encoder.encode(masterPassword);
  let keyMaterial;
  try {
    keyMaterial = await crypto.subtle.importKey(
      'raw', passwordBytes, { name: 'PBKDF2' }, false, ['deriveKey']
    );
  } finally {
    passwordBytes.fill(0);
  }

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'HMAC', hash: 'SHA-256', length: KEY_LENGTH_BITS },
    false,
    ['sign']
  );
}

function toBase64Url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export async function derivePassword(key, serviceIdentifier, config) {
  const canonicalService = canonicalServiceIdentifier(serviceIdentifier);
  const coreLength = config.length - config.prefix.length - config.suffix.length;
  if (coreLength < MIN_DERIVED_LENGTH) {
    throw new Error('The prefix and suffix must leave at least one derived character.');
  }
  const signature = new Uint8Array(
    await crypto.subtle.sign('HMAC', key, encoder.encode(canonicalService))
  );
  const encodedSegment = toBase64Url(signature).slice(0, coreLength);
  if (encodedSegment.length !== coreLength) {
    throw new Error('The requested derived segment exceeds the cryptographic output length.');
  }
  return `${config.prefix}${encodedSegment}${config.suffix}`;
}
