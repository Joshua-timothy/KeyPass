# Keyform — Reverse-engineering notes

## Reference inspected

Public repository: [Joshua-timothy/PassMorph](https://github.com/Joshua-timothy/PassMorph), in particular its `script.js` and README. This update is based on the source available on 18 October 2026. Keyform retains its independent name, interface, and styles.

## Reference behavior reconstructed

1. Service identifier canonicalization: lowercase, trim outer whitespace, strip all characters except ASCII letters, digits, and hyphens.
2. Service salt material: SHA-256 of the canonical identifier.
3. Application salt: 16 bytes `[15, 122, 45, 90, 16, 23, 78, 101, 19, 55, 11, 22, 33, 44, 55, 66]`.
4. PBKDF2: SHA-256, 500,000 iterations, salt equal to application salt followed by the service hash, 256-bit non-exportable HMAC key.
5. Output: HMAC-SHA256 over the canonical service identifier, converted to unpadded Base64URL, truncated to the derived segment length.
6. Final output: prefix + derived segment + suffix.
7. Defaults: total length 24, prefix `$J0$hu@`, suffix `o8o`.
8. Input rule in the reference source: master key is at least 10 characters and contains lowercase, uppercase, a digit, and a non-alphanumeric character. Service identifier input is at least 3 typed characters before canonicalization.
9. The reference source clears its master-password input after derivation and stores settings in localStorage. Keyform also clears the master key after generation, but deliberately leaves all settings in memory only to retain its no-browser-storage policy.

## Decisions retained for security and product coherence

- The Keyform UI, brand, light/dark toggle, custom scrollbar, dialogs, and responsive layout remain unchanged in design.
- HMAC keys remain non-exportable. Mutable password byte buffers are cleared after import, with the limitation that JavaScript cannot guarantee complete memory zeroization.
- User input and generated output are not logged. No application API calls, analytics, or browser storage are used.
- Settings are bounded (length 10–40; prefix/suffix up to 30 characters; control characters rejected). This is more restrictive than the reference in a few unusual settings edge cases, but does not change output when the same accepted settings are used.
- Theme and settings are session-only, unlike the reference's localStorage persistence.
- Settings enforce at least one derived character, matching the reference's minimum, rather than the previous Keyform rule requiring at least ten derived characters.

## Validation

The automated suite compares Keyform's output with an independent test implementation of the public reference sequence and checks deterministic output, service separation, defaults, canonicalization, exact output length, affix assembly, and invalid configurations. A final browser/device test on HTTPS or localhost is still recommended before deploying this for real accounts.
