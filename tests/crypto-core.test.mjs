import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import {
  deriveHmacKey,
  derivePassword,
  validateSettings,
  validateMaster,
  canonicalServiceIdentifier,
  requirementsFor,
  ITERATIONS,
  APP_SALT,
  DEFAULT_SETTINGS
} from '../crypto-core.js';

globalThis.crypto ??= webcrypto;
const master = 'FjordCobalt!9283';

// Independent reference implementation following the public PassMorph source:
// service hash -> app salt + service hash -> PBKDF2 key -> HMAC service -> Base64URL -> truncate.
async function sourceReference(masterPassword, inputService, config) {
  const encode = (value) => new TextEncoder().encode(value);
  const service = String(inputService).toLowerCase().trim().replace(/[^a-z0-9-]/g, '');
  const referenceAppSalt = new Uint8Array([15, 122, 45, 90, 16, 23, 78, 101, 19, 55, 11, 22, 33, 44, 55, 66]);
  const serviceHash = new Uint8Array(await crypto.subtle.digest('SHA-256', encode(service)));
  const salt = new Uint8Array(referenceAppSalt.length + serviceHash.length);
  salt.set(referenceAppSalt);
  salt.set(serviceHash, referenceAppSalt.length);
  const keyMaterial = await crypto.subtle.importKey('raw', encode(masterPassword), { name: 'PBKDF2' }, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 500_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign']
  );
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, encode(service)));
  let binary = '';
  for (const byte of signature) binary += String.fromCharCode(byte);
  const encoded = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const segmentLength = config.length - config.prefix.length - config.suffix.length;
  return `${config.prefix}${encoded.slice(0, segmentLength)}${config.suffix}`;
}

test('uses the reference work factor and default settings', () => {
  assert.equal(ITERATIONS, 500_000);
  assert.deepEqual(DEFAULT_SETTINGS, { length: 24, prefix: '$J0$hu@', suffix: 'o8o' });
  assert.deepEqual([...APP_SALT], [15, 122, 45, 90, 16, 23, 78, 101, 19, 55, 11, 22, 33, 44, 55, 66]);
  assert.equal(validateMaster(master), '');
  assert.match(validateMaster('password'), /at least 10 characters/);
  assert.equal(requirementsFor('ABCdef123!').length, true);
  assert.equal(requirementsFor('ABCdef123').symbol, false);
});

test('canonicalizes service identifiers like the reference implementation', () => {
  assert.equal(canonicalServiceIdentifier('  GitHub.com  '), 'githubcom');
  assert.equal(canonicalServiceIdentifier('Work-VPN!'), 'work-vpn');
  assert.equal(canonicalServiceIdentifier('A B_C.123'), 'abc123');
});

test('derives the same output as an independent implementation of the public source', async () => {
  const config = { ...DEFAULT_SETTINGS };
  const key = await deriveHmacKey(master, 'GitHub.com');
  const actual = await derivePassword(key, 'GitHub.com', config);
  const reference = await sourceReference(master, 'GitHub.com', config);
  assert.equal(actual, reference);
  assert.equal(actual.length, 24);
  assert.equal(actual, '$J0$hu@6IkFJWTtlfMunko8o');
  assert.ok(actual.startsWith('$J0$hu@'));
  assert.ok(actual.endsWith('o8o'));
});

test('different service identifiers produce different deterministic outputs', async () => {
  const settings = { ...DEFAULT_SETTINGS };
  const githubKey = await deriveHmacKey(master, 'github.com');
  const gmailKey = await deriveHmacKey(master, 'gmail.com');
  const github = await derivePassword(githubKey, 'github.com', settings);
  const gmail = await derivePassword(gmailKey, 'gmail.com', settings);
  assert.notEqual(github, gmail);
  const repeated = await derivePassword(await deriveHmacKey(master, 'GITHUB.COM'), 'GITHUB.COM', settings);
  assert.equal(github, repeated);
});

test('uses exact prefix/suffix lengths and rejects impossible configurations', async () => {
  const settings = { length: 24, prefix: 'pre-9!', suffix: '-end2' };
  assert.equal(validateSettings(settings), '');
  const key = await deriveHmacKey(master, 'test.example');
  const password = await derivePassword(key, 'test.example', settings);
  assert.equal(password.length, 24);
  assert.ok(password.startsWith(settings.prefix));
  assert.ok(password.endsWith(settings.suffix));
  assert.match(validateSettings({ length: 10, prefix: '0123456789', suffix: '' }), /at least 1 character/);
  assert.match(validateSettings({ length: 20, prefix: 'bad\nvalue', suffix: '' }), /control characters/);
  assert.match(validateSettings({ length: 41, prefix: '', suffix: '' }), /between 10 and 40/);
});
