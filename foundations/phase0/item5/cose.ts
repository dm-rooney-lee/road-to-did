/**
 * 05 — CBOR / COSE (the binary cousins of JSON / JWS)
 *
 * READ FIRST  ./cose.notes.html  (CBOR byte format + COSE_Sign1 structure)
 * IMPLEMENT   One function per section. Fill in each body.
 * VERIFY      npx tsx --test foundations/phase0/item5/cose.test.ts
 *
 * Item 05 builds on Item 02's signing primitives. The crypto is unchanged —
 * still ES256, still `dsaEncoding: 'ieee-p1363'`. What's new is the envelope:
 * CBOR instead of base64url-of-JSON, and COSE_Sign1's four-element array
 * instead of JWS's three "."-separated segments.
 *
 *   JWS                              COSE_Sign1
 *   ───────────────────────────────  ─────────────────────────────────────────
 *   base64url(JSON header)           CBOR-encoded map, then wrapped in bstr
 *   "."                              array-of-4 in CBOR
 *   base64url(JSON payload)          payload as bstr (or nil)
 *   "."                              signature as bstr
 *   base64url(signature bytes)       optionally tagged with CBOR tag 18
 *
 * The lab uses a minimal CBOR subset: unsigned int, negative int, byte string,
 * text string, array, map. That's enough for COSE_Sign1.
 */

import {sign, verify, type KeyObject} from 'node:crypto';

function TODO(label: string): never {
    throw new Error(`TODO — ${label} not implemented`);
}

// ============================================================
// The CBOR value type used in this lab
// ============================================================
//   number  → CBOR unsigned int (≥ 0) or negative int (< 0)
//   Buffer  → CBOR byte string  (major type 2)
//   string  → CBOR text string  (major type 3, UTF-8)
//   array   → CBOR array        (major type 4)
//   Map     → CBOR map          (major type 5; keys are number or string)
//
// JS Map preserves insertion order, which matches CBOR's map ordering.
// (Real-world COSE uses *canonical* CBOR with sorted keys — covered in Lesson 3.)
// ============================================================

export type CborValue =
    | number
    | Buffer
    | string
    | CborValue[]
    | Map<number | string, CborValue>;

// ============================================================
// decodeCbor — PRE-PROVIDED HELPER (read but do not modify)
//
//   The dual of `encodeCbor`. Decodes a CBOR-encoded Buffer into a JS value
//   from the CborValue type, plus the number of bytes consumed (useful for
//   parsing structures one element at a time).
//
//   Supports the same subset as encodeCbor: major types 0–5.
//   Will throw on unsupported types (tagged values, floats, simples, etc.) —
//   except for the optional leading CBOR tag 18 (which COSE_Sign1 may carry).
// ============================================================

export function decodeCbor(bytes: Buffer, offset = 0): { value: CborValue; bytesRead: number } {
    const startOffset = offset;
    const initial = bytes[offset];
    const majorType = initial >> 5;
    const argByte = initial & 0x1f;
    offset += 1;

    // Skip an optional CBOR tag (only tag 18 is recognized — the COSE_Sign1 tag)
    if (majorType === 6 && argByte === 18) {
        const inner = decodeCbor(bytes, offset);
        return { value: inner.value, bytesRead: 1 + inner.bytesRead };
    }

    let arg: number;
    if (argByte < 24)        { arg = argByte; }
    else if (argByte === 24) { arg = bytes[offset];                          offset += 1; }
    else if (argByte === 25) { arg = bytes.readUInt16BE(offset);             offset += 2; }
    else if (argByte === 26) { arg = bytes.readUInt32BE(offset);             offset += 4; }
    else if (argByte === 27) { arg = Number(bytes.readBigUInt64BE(offset));  offset += 8; }
    else { throw new Error(`unsupported CBOR additional info: ${argByte}`); }

    switch (majorType) {
        case 0: // unsigned int
            return { value: arg, bytesRead: offset - startOffset };
        case 1: // negative int
            return { value: -1 - arg, bytesRead: offset - startOffset };
        case 2: { // byte string
            const buf = bytes.subarray(offset, offset + arg);
            return { value: Buffer.from(buf), bytesRead: offset - startOffset + arg };
        }
        case 3: { // text string
            const str = bytes.subarray(offset, offset + arg).toString('utf8');
            return { value: str, bytesRead: offset - startOffset + arg };
        }
        case 4: { // array
            const items: CborValue[] = [];
            let cursor = offset;
            for (let i = 0; i < arg; i++) {
                const item = decodeCbor(bytes, cursor);
                items.push(item.value);
                cursor += item.bytesRead;
            }
            return { value: items, bytesRead: cursor - startOffset };
        }
        case 5: { // map
            const m = new Map<number | string, CborValue>();
            let cursor = offset;
            for (let i = 0; i < arg; i++) {
                const k = decodeCbor(bytes, cursor); cursor += k.bytesRead;
                const v = decodeCbor(bytes, cursor); cursor += v.bytesRead;
                if (typeof k.value !== 'number' && typeof k.value !== 'string') {
                    throw new Error('only number/string map keys are supported in this lab');
                }
                m.set(k.value, v.value);
            }
            return { value: m, bytesRead: cursor - startOffset };
        }
        default:
            throw new Error(`unsupported CBOR major type: ${majorType}`);
    }
}

// ============================================================
// Section 1 — Encode a CborValue as CBOR bytes
//
//   Serialize a JS value of type CborValue into its canonical CBOR byte
//   representation, per RFC 8949. The function must support the six cases
//   listed in the CborValue type above.
//
//   For each value, CBOR emits an *initial byte* that packs:
//     • the top 3 bits = major type (0..5)
//     • the bottom 5 bits = either the value itself (0..23) or a marker
//       indicating how many bytes of "argument" follow (24, 25, 26, 27 →
//       1, 2, 4, 8 bytes, big-endian)
//   Followed by:
//     • for ints: nothing more (the argument IS the value, or -(arg+1) for nint)
//     • for bstr/tstr: `arg` bytes of payload
//     • for array: `arg` recursively-encoded values
//     • for map:   `arg` (key, value) pairs, each recursively encoded
//
//   This function MUST NOT throw on the value types listed in CborValue.
//   For an unsupported runtime type (e.g. boolean), throwing is fine.
// ============================================================

export function encodeCbor(value: CborValue): Buffer {
    return TODO('encodeCbor');
}

// ============================================================
// Section 2 — Build a COSE_Sign1 over a payload (ES256)
//
//   Produce a COSE_Sign1 message per RFC 9052 §4.2: a four-element CBOR
//   array, optionally wrapped in CBOR tag 18.
//
//   The four elements (in this order):
//     1. protected   — bstr containing the CBOR-encoded protected header map.
//                      MUST be encoded as bytes EVEN IF the inner map is empty.
//                      For this lab, the protected header is the single-entry
//                      map { 1: -7 }  // alg = ES256
//     2. unprotected — map. For this lab, the single-entry map { 4: kid }
//                      where 4 is the COSE label for "kid" (key identifier).
//     3. payload     — bstr (the bytes being signed)
//     4. signature   — bstr (raw R‖S, 64 bytes for ES256)
//
//   The signature is NOT over the payload directly. It's over the CBOR
//   encoding of the *Sig_structure* (RFC 9052 §4.4):
//
//       Sig_structure = [
//           context:         "Signature1",
//           body_protected:  <bytes of element 1 above>,
//           external_aad:    <Buffer of length 0>,
//           payload:         <bytes of element 3 above>,
//       ]
//
//   So the signing flow is:
//     a. Build the protected header map and encode it → protected_bytes
//     b. Build the Sig_structure array as above
//     c. CBOR-encode it → to_be_signed
//     d. Sign to_be_signed with ES256 (raw R‖S, not DER — Item 02 Lesson 3)
//     e. Assemble the four-element array and CBOR-encode it
//     f. Prepend CBOR tag 18 (one byte: 0xd2)
//
//   Inputs:
//     payload    — the bytes to sign
//     kid        — key identifier bytes (placed in unprotected header)
//     privateKey — EC P-256 private KeyObject
//
//   Returns: the tagged COSE_Sign1 as a Buffer.
// ============================================================

export function buildCoseSign1(
    payload: Buffer,
    kid: Buffer,
    privateKey: KeyObject,
): Buffer {
    return TODO('buildCoseSign1');
}

// ============================================================
// Section 3 — Verify a COSE_Sign1 (ES256)
//
//   Decode an incoming COSE_Sign1 (tagged or untagged) and decide whether
//   to trust it.
//
//   Inputs:
//     signedBytes — a COSE_Sign1 produced by some signer
//     publicKey   — EC P-256 public KeyObject the verifier trusts
//
//   Return shape (every field populated on every call):
//     valid           — true if BOTH conditions hold:
//                         (i)  protected.alg === -7  (ES256)
//                         (ii) the signature verifies over the reconstructed
//                              Sig_structure
//     payload         — the decoded payload bytes (returned regardless of validity)
//     protectedHeader — the decoded protected header map (returned regardless of validity)
//
//   When valid is false, payload/protectedHeader are still returned so the
//   caller can inspect what was claimed — but they MUST NOT be trusted.
//
//   Check order (short-circuits on the first failure):
//     1. alg discipline   — protected.alg must equal -7 (ES256)
//     2. signature        — verify over the reconstructed Sig_structure
//   Mirror Item 02: alg is a precondition that runs BEFORE crypto.
// ============================================================

export type CoseVerifyResult = {
    valid: boolean;
    payload: Buffer;
    protectedHeader: Map<number | string, CborValue>;
};

export function verifyCoseSign1(
    signedBytes: Buffer,
    publicKey: KeyObject,
): CoseVerifyResult {
    return TODO('verifyCoseSign1');
}

// ============================================================
// LESSONS (read after implementing and running the tests)
// ============================================================
//
// Lesson 1 — Integer keys make COSE maps tiny
//   COSE deliberately uses small integers as map labels instead of strings.
//   `{ alg: -7 }` in COSE encodes as 4 bytes:
//
//       a1 01 26      // map(1) { 1 (alg) -> -7 (ES256) }
//
//   The equivalent JOSE header in JWS is `{"alg":"ES256"}`, which after
//   JSON serialization + base64url is 18+ bytes. For mDL/mdoc — designed to
//   travel over NFC, BLE, and QR codes — the wire savings matter. Same
//   information; an order of magnitude less space.
//
//   The flipside: you must memorize (or look up) the label registry. There's
//   no human-readable hint in the bytes that `1` means `alg`. Tooling fills
//   the gap — COSE parsers map integers back to names on display.
//
// Lesson 2 — Sig_structure: the indirection that gets signed
//   What the COSE_Sign1 array *contains* and what was *actually signed* are
//   not the same bytes. The signer constructs an auxiliary structure:
//
//       ["Signature1", protected_bstr, ext_aad, payload]
//
//   CBOR-encodes it, and signs THAT. The receiver, on verify, has to
//   reconstruct the exact same Sig_structure from the parts it received.
//
//   Why the indirection? It binds the signature to:
//     • a literal context label ("Signature1") that prevents confusion with
//       other COSE structures (Sign, MAC0, etc.) — algorithm-confusion's
//       binary cousin
//     • the protected header bytes exactly as they were on the wire — so an
//       attacker can't substitute a different alg or kid
//     • the external AAD (additional authenticated data not transmitted) —
//       so the protocol can bind extra context without putting it in the
//       message
//
//   JWS achieves the same property differently: the signing input is the
//   literal ASCII string `base64url(header) + "." + base64url(payload)`. No
//   context label, because JWS has a single canonical compact form. COSE has
//   multiple message types (Sign / Sign1 / MAC / MAC0 / Encrypt / Encrypt0)
//   sharing the same envelope, so the context label disambiguates.
//
// Lesson 3 — CBOR has multiple valid encodings; mdoc requires the canonical one
//   The number 23 can be encoded as `0x17` (one byte) OR as `0x18 0x17`
//   (two bytes with the argument explicitly). Both decode to 23. Both are
//   valid CBOR per RFC 8949.
//
//   This is fine for general CBOR. It's a disaster for signed CBOR: if
//   the issuer produces one encoding and the verifier re-encodes it
//   differently, the Sig_structure hashes differently, and the signature
//   fails — even though the data is identical.
//
//   The fix is "core deterministic encoding" (RFC 8949 §4.2):
//     • integers use the shortest possible encoding
//     • maps are sorted by key (numerically/byte-lexicographically)
//     • no indefinite-length forms
//     • no leading zeros, no NaN variants, etc.
//
//   ISO 18013-5 (mDL/mdoc) requires this canonical form. SD-JWT VC dodges
//   the question by using JSON canonicalization at a different layer.
//   The lab's `encodeCbor` should naturally emit deterministic bytes for
//   the supported types — short-form ints, no surprise paddings — because
//   it implements one and only one encoding per value.
