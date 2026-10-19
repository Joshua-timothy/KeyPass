# Keyform

**Passwords, derived.** Keyform is a mobile-first, local-only deterministic password generator. It keeps the existing Keyform interface, dark-mode toggle, and custom scrollbar while using a derivation profile compatible with the public PassMorph source.

## Derivation behavior

For the same master key, service identifier, total length, prefix, and suffix, the output is deterministic. The current compatibility profile follows this sequence:

1. Canonicalize the service identifier by lowercasing it, trimming outer whitespace, then removing every character except ASCII letters, digits, and hyphens. For example, `GitHub.com` becomes `githubcom`.
2. SHA-256 hash the canonical service identifier.
3. Concatenate the 16-byte public application salt with that 32-byte service hash.
4. Use PBKDF2-HMAC-SHA256 with **500,000 iterations** and the combined salt to derive a non-exportable 256-bit HMAC-SHA256 key from the exact UTF-8 bytes of the master key. The master key is not Unicode-normalized.
5. HMAC-SHA256-sign the canonical service identifier with that derived key.
6. Encode the 32-byte signature as unpadded Base64URL and truncate it to `total length − prefix length − suffix length` characters.
7. Assemble `prefix + encoded segment + suffix`.

Default settings match the current reference source:

| Setting | Default |
| --- | --- |
| Total length | 24 characters |
| Prefix | `$J0$hu@` |
| Suffix | `o8o` |
| PBKDF2 iterations | 500,000 |

Static prefixes and suffixes help meet a service's character rules but add no entropy. The HMAC-derived Base64URL segment uses letters, digits, hyphens, and underscores; with empty affixes, the result is not guaranteed to contain a symbol required by every website. The source's default affixes include symbols.

## Security and privacy

- All cryptographic work is done locally with the browser's Web Crypto API.
- Keyform does not send inputs or generated passwords to an application server, and it does not use application network calls, analytics, cookies, local storage, session storage, or IndexedDB.
- The master-key field is cleared after each generation. A fresh master key is required for each new service/password generation; the HMAC key is not cached between generations.
- The mutable UTF-8 byte buffer is cleared after Web Crypto imports it. JavaScript cannot guarantee zeroization of immutable strings, browser-internal copies, operating-system memory, or input methods.
- The clipboard can retain copied passwords, and a compromised device/browser, malicious extension, or modified hosted code can expose secrets.
- The composition policy requires 10+ characters and lowercase, uppercase, numeric, and non-alphanumeric characters. This is only a minimum filter, not proof of entropy. Use a long, unique master passphrase.
- Static hosting headers and the in-page Content Security Policy are included. Deploy over HTTPS; Web Crypto is unavailable on most insecure origins.

## UI behavior

- Responsive mobile-first Keyform interface.
- Light/dark toggle; theme choice remains in memory and is not persisted.
- Custom, theme-aware draggable scrollbar; native browser scrolling continues to handle touch, wheel, keyboard, and assistive-technology interaction.
- Password settings are session-only. Defaults are restored after reload; only non-secret configuration values are visible in the settings UI.
- Clear-session action clears the current master key, service identifier, and generated result.

## Run locally

Serve this directory through localhost with any static file server. For example, with Python installed:

```bash
python -m http.server 8080
```

Open `http://localhost:8080` in a modern browser. Deploy the directory as a static site on Netlify; `netlify.toml` and `_headers` contain the intended security headers.

## Tests

```bash
npm test
```

The tests verify the iteration count and defaults, service canonicalization, output reproducibility against an independent implementation of the public source's derivation sequence, service separation, affix assembly, and configuration validation.

## Compatibility notes

The cryptographic sequence and defaults are now aligned with the public source available at [Joshua-timothy/PassMorph](https://github.com/Joshua-timothy/PassMorph). Outputs can still differ if any input or setting differs, or if that upstream algorithm changes. If this app is used to reproduce an existing account password, verify the exact output against the original tool before relying on it for account access.
