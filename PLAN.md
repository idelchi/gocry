# PLAN: Add Authenticity To Non-Deterministic Mode

## Goals
- Replace the current unauthenticated AES-CTR usage in non-deterministic mode with an authenticated construction.
- Leave deterministic AES-SIV mode untouched.
- Keep the solution simple and idiomatic for Go’s standard library and minimal new dependencies.

## Approach
1. **Switch to Encrypt-Then-MAC**
   - Keep AES-CTR for confidentiality but pair it with an HMAC-SHA256 tag (encrypt-then-MAC).
   - This requires no compatibility bridge; ciphertext layout can be redesigned freely (e.g. `[MAGIC|VERSION|IV|CT|TAG]`).

2. **Key Schedule**
   - Derive two subkeys from the existing 32-byte input using HKDF-SHA256 (`info = "gocry/ctr+mac"`).
   - Use the first 16 bytes (or 32 for AES-CTR-256 if desired) for AES-CTR, the next 32 bytes for HMAC.

3. **Streaming Implementation**
   - When encrypting: write header + IV, stream AES-CTR output while feeding the same bytes into HMAC, then append the tag once finished.
   - When decrypting: read header and IV, capture ciphertext, verify the trailing tag via `hmac.Equal`, then decrypt if verification succeeds.

4. **Line Mode Support**
   - Reuse the same helper to produce/consume `[header | IV | ciphertext | tag]` blobs, then Base64 encode for directive output.

5. **Documentation**
   - Update README and package docs to note the new authenticated, randomized mode and document the on-disk format.

## Why Not Switch to a Full AEAD?
- AES-GCM or XChaCha20-Poly1305 would require buffering entire inputs (or extra complexity for chunking) because Go’s `cipher.AEAD` API seals whole messages at once, undermining the existing streaming design.
- AES-CTR + HMAC keeps the code path straightforward, needs no third-party AEAD wrappers, and still provides strong confidentiality and integrity guarantees when used with unique IVs.

## Tests
- No changes required—the existing test harness already exercises encrypt/decrypt round-trips; tampering detection can be deferred to future targeted tests if desired.

## Deliverables
- Updated non-deterministic encryption/decryption path with Encrypt-then-MAC keys + format.
- Revised docs reflecting the authenticated design.
