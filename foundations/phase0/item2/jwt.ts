/**
 * 02 — JWT Family
 *
 * READ FIRST  ./jwt.notes.html  (interactive concepts + JWS builder + alg:none sim)
 * IMPLEMENT   One function per section. Fill in each body.
 * VERIFY      npm test
 */

import {type KeyObject, sign, verify} from 'node:crypto';

function TODO(label: string): never {
    throw new Error(`TODO — ${label} not implemented`);
}

// ============================================================
// Section 1 — Encode a compact JWS (ES256)
//
//   Inputs:
//     header     — JSON-serializable header; `alg` must be 'ES256'
//     payload    — JSON-serializable claims set
//     privateKey — EC P-256 private KeyObject
//
//   1a. token is three base64url-charset segments joined by "."
//   1b. encodedHeader   = base64url(JSON(header))
//   1c. encodedPayload  = base64url(JSON(payload))
//   1d. signatureBytes  = raw R‖S ECDSA-P256 signature over the ASCII
//                         signing input `encodedHeader + "." + encodedPayload`
//                         (exactly 64 bytes for P-256; NOT DER)
//   1e. token           = `${encodedHeader}.${encodedPayload}.${encodedSignature}`
//                         where encodedSignature = base64url(signatureBytes)
// ============================================================

export function encodeJwsCompact(
    header: { alg: 'ES256'; typ: 'JWT'; [k: string]: unknown },
    payload: Record<string, unknown>,
    privateKey: KeyObject,
): {
    encodedHeader: string;
    encodedPayload: string;
    signatureBytes: Buffer;
    encodedSignature: string;
    token: string;
} {
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');

    // signing input is the ASCII string base64url(header) + "." + base64url(payload)
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    // JWS requires raw R∥S concatenation, not Node's default DER
    const signatureBytes = sign('sha256', Buffer.from(signingInput), {
        key: privateKey,
        dsaEncoding: 'ieee-p1363',
    });
    const encodedSignature = signatureBytes.toString('base64url');
    const token = `${signingInput}.${encodedSignature}`;

    return {
        encodedHeader,
        encodedPayload,
        signatureBytes,
        encodedSignature,
        token,
    };
}

// ============================================================
// Section 2 — Verify a compact JWS (ES256)
//
//   Decode the token, then decide whether to trust it. The function ALWAYS
//   returns all three fields on every call — `header` and `payload` are
//   decoded regardless of validity (so the caller can inspect what was
//   claimed), and `valid` is the separate "should I trust this?" gate.
//
//   Inputs:
//     token       — "encodedHeader.encodedPayload.encodedSignature"
//     publicKey   — EC P-256 public KeyObject the verifier trusts
//     expectedAlg — algorithm the verifier WILL accept (e.g. 'ES256')
//
//   Return shape (every field populated on every call):
//     header  — JSON-decoded header
//     payload — JSON-decoded payload
//     valid   — true if BOTH conditions hold:
//                 (i)  header.alg === expectedAlg
//                 (ii) the signature verifies against the signing input
//                      `encodedHeader + "." + encodedPayload` under publicKey
//               Otherwise false. When false, header/payload are still
//               returned but a caller MUST NOT trust them.
// ============================================================

export function verifyJwsCompact(
    token: string,
    publicKey: KeyObject,
    expectedAlg: 'ES256',
): {
    valid: boolean;
    header: { alg: string; typ?: string; [k: string]: unknown };
    payload: Record<string, unknown>;
} {
    const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');

    // decode header and payload (returned to the caller regardless of validity)
    const header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());

    // alg check is a precondition: rejected before any crypto runs
    if (header.alg !== expectedAlg) {
        return {valid: false, header, payload};
    }

    // signature check: bind verification result directly to `valid`
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const valid = verify(
        'sha256',
        Buffer.from(signingInput),
        {key: publicKey, dsaEncoding: 'ieee-p1363'},
        Buffer.from(encodedSignature, 'base64url'),
    );

    return {valid, header, payload};
}

// ============================================================
// Section 3 — Export an EC P-256 public key as a JWK
//
//   Convert a Node KeyObject (the in-memory key handle from
//   `generateKeyPairSync`, `createPublicKey`, etc.) into its JSON Web Key
//   representation — the serialized JSON form JWS/JWT systems exchange
//   over the wire.
//
//   Inputs:
//     publicKey — EC P-256 public KeyObject
//
//   Return shape: see the function signature below.
// ============================================================

export function exportPublicJwk(publicKey: KeyObject): {
    kty: 'EC';
    crv: 'P-256';
    x: string;
    y: string;
} {
    const jwk = publicKey.export({format: 'jwk'});
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
        throw new Error(
            `exportPublicJwk: expected an EC P-256 public key (got kty=${jwk.kty}, crv=${jwk.crv})`,
        );
    }
    // TypeScript narrows jwk.x and jwk.y to `string` here — no `!` needed.
    return {
        kty: 'EC',
        crv: 'P-256',
        x: jwk.x,
        y: jwk.y,
    };
}

// ============================================================
// LESSONS (read after implementing and running `npm test`)
// ============================================================
//
// Lesson 1 — base64url is base64 with two character swaps and no padding
//   Standard base64 emits '+', '/', and '=' padding. None of those are
//   URL-safe ('+' is interpreted as space in query strings, '/' is a path
//   separator, '=' is reserved). base64url swaps the alphabet ('+' → '-',
//   '/' → '_') and drops the '=' padding entirely. The decoded length is
//   recoverable from the encoded length, so padding isn't strictly needed.
//
//   Node has it built in: `buf.toString('base64url')` and
//   `Buffer.from(s, 'base64url')`. Every segment of a compact JWS — header,
//   payload, signature — uses this encoding.
//
// Lesson 2 — The 'alg: none' attack and verifier discipline
//   In 2015 several mainstream JWT libraries were found to trust the
//   `alg` field in the (attacker-controlled) header to choose a verifier:
//
//     alg: 'ES256' → run ECDSA verify
//     alg: 'none'  → return true, skip verification
//
//   An attacker crafted `{alg: "none"}` with an empty signature, the
//   library returned "valid", and the payload was trusted.
//
//   The general fix is a single discipline: the verifier knows what
//   algorithm it expects (here, `expectedAlg: 'ES256'`). Reject anything
//   else. Never use `header.alg` to *select* the verifier — only to
//   *match* against the expected value.
//
//   The same discipline kills the "algorithm confusion" variant — where
//   a token signed `ES256` is replayed with `alg: 'HS256'` so the verifier
//   uses HMAC with the (public!) public key as the symmetric secret.
//
// Lesson 3 — ECDSA signature format: DER vs JOSE raw
//   Node's `sign('sha256', msg, ecKey)` returns a DER-encoded ECDSA
//   signature: 70–72 bytes of ASN.1 with length prefixes. JWS requires
//   raw `R∥S` concatenation — for P-256, exactly 64 bytes (two 32-byte
//   integers, no framing).
//
//   Switch Node into JOSE form with `dsaEncoding: 'ieee-p1363'`. Forget
//   this and your token will *look* fine in jwt.io but real verifiers
//   (browsers, other-language libraries) will reject it with no obvious
//   clue why — they'll see the wrong number of bytes and bail before
//   even attempting the verification math.
