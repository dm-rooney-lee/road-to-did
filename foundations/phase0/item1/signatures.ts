/**
 * 01 — Signatures & Hashing
 *
 * READ FIRST  ./signatures.notes.html  (interactive concepts + sign/verify demo)
 * IMPLEMENT   One function per section. Fill in each body.
 * VERIFY      npm test
 */

import {generateKeyPairSync, hash, type KeyObject, sign, verify} from 'node:crypto';

function TODO(label: string): never {
    throw new Error(`TODO — ${label} not implemented`);
}

// ============================================================
// Section 1 — Ed25519
//   1a. Generate Ed25519 keypair               → publicKey, privateKey
//   1b. Sign `message` with Ed25519            → signature
//   1c. Verify signature against `message`     → messageValid
//   1d. Verify signature against `tampered`    → tamperedValid
// ============================================================

export function signAndVerifyWithEd25519(
    message: Buffer,
    tampered: Buffer,
): {
    publicKey: KeyObject;
    privateKey: KeyObject;
    signature: Buffer;
    messageValid: boolean;
    tamperedValid: boolean;
} {
    const {privateKey, publicKey} = generateKeyPairSync('ed25519');
    const signature = sign(null, message, privateKey);
    const messageValid = verify(null, message, publicKey, signature);
    const tamperedValid = verify(null, tampered, publicKey, signature);

    return {
        publicKey,
        privateKey,
        signature,
        messageValid,
        tamperedValid,
    };
}

// ============================================================
// Section 2 — ECDSA P-256
//   2a. Generate ECDSA P-256 keypair   → publicKey, privateKey
//   2b. Sign `message` with ECDSA      → signature
//   2c. Verify signature               → valid
// ============================================================

export function signAndVerifyWithEcdsaP256(message: Buffer): {
    publicKey: KeyObject;
    privateKey: KeyObject;
    signature: Buffer;
    valid: boolean;
} {
    const {privateKey, publicKey} = generateKeyPairSync('ec', {namedCurve: 'P-256'});
    const signature = sign('sha256', message, privateKey);
    const valid = verify('sha256', message, publicKey, signature);

    return {
        publicKey,
        privateKey,
        signature,
        valid,
    };
}

// ============================================================
// Section 3 — SHA-256 with ECDSA P-256 (the ES256 / JWT pattern)
//   3a. Compute SHA-256 hex digest of `message` (for display)     → digestHex
//   3b. Compute SHA-256 digest of `message` as Buffer (same hash) → digestBytes
//   3c. Sign `message` with ECDSA P-256 + SHA-256                 → signature
//   3d. Verify signature                                          → signatureValid
//
//   Note: Node's `sign('sha256', message, key)` internally hashes the
//   message with SHA-256 and then signs the 32-byte digest with ECDSA.
//   The digest we compute manually in 3a / 3b is the same hash Node
//   uses internally — we just expose it for inspection. This is
//   exactly the canonical JWT `ES256` signing pattern.
// ============================================================

export function hashAndSignWithEcdsaP256(message: Buffer): {
    digestHex: string;
    digestBytes: Buffer;
    publicKey: KeyObject;
    privateKey: KeyObject;
    signature: Buffer;
    signatureValid: boolean;
} {
    const {privateKey, publicKey} = generateKeyPairSync('ec', {namedCurve: 'P-256'});
    const digestHex = hash('sha256', message);
    const digestBytes = hash('sha256', message, 'buffer');
    const signature = sign('sha256', message, privateKey);
    const signatureValid = verify('sha256', message, publicKey, signature);

    return {
        digestHex,
        digestBytes,
        publicKey,
        privateKey,
        signature,
        signatureValid,
    };
}

// ============================================================
// LESSONS (read after implementing and running `npm test`)
// ============================================================
//
// Lesson 1 — Deterministic vs random nonces
//   Run `npm test` twice and compare the signatures returned by the two
//   sign functions. (Easiest: log them, or write a quick scratch script
//   that calls each function twice with the same message and prints the
//   signatures as hex.)
//
//   You'll see:
//     • Ed25519 returns the SAME signature on every call — for the same
//       (private key, message), it always produces the same 64 bytes.
//     • ECDSA returns a DIFFERENT signature on every call — even with
//       the same key and message, the bytes change each time.
//
//   Why: ECDSA's signing math requires a random per-signature value
//   called `k` (a 'nonce'). The signature embeds `k`, so different `k`
//   → different signature. Ed25519, by contrast, derives its `k`
//   deterministically by hashing the private key + message together, so
//   the same inputs always produce the same `k` and thus the same sig.
//
//   This is more than a curiosity. If ECDSA ever reuses `k` for two
//   different messages signed with the same key, the private key is
//   mathematically recoverable from the two signatures. Sony's
//   PlayStation 3 firmware signing was broken in 2010 exactly this
//   way — they hard-coded `k`. Ed25519's deterministic construction
//   makes this whole class of bug impossible.
//
// Lesson 2 — Sign-over-hash (the ES256 / JWT pattern)
//   `hashAndSignWithEcdsaP256` signs `message` with ECDSA P-256 + SHA-256.
//   Internally, Node first hashes the message with SHA-256, then signs the
//   resulting 32-byte digest with ECDSA. That's exactly the JWT `ES256`
//   algorithm.
//
//   We separately compute the SHA-256 digest ourselves (`digestHex` and
//   `digestBytes`) to make the hash inspectable. The bytes you see in
//   `digestBytes` are the same 32 bytes Node hashes internally before
//   signing — exposing them changes nothing about the signature, it just
//   lets you observe what's happening.
//
//   Why this pattern matters:
//     • Signing primitives operate on fixed-size inputs. A hash turns any
//       message — 9 bytes or 9 GB — into a 32-byte fingerprint.
//     • Hashing a big message is far cheaper than signing a big message.
//     • The digest can be transmitted/stored independently of the data
//       (e.g., a 4 GB binary can be signed by signing only its 32-byte
//       SHA-256, without the signer ever touching the bytes).
//
//   Ed25519 is different: it does NOT externally hash. `sign(null, msg, key)`
//   for Ed25519 takes the raw message and hashes internally with SHA-512
//   as part of EdDSA. You don't pre-hash with Ed25519 in real code — if
//   you tried (signing the SHA-256 of a message with Ed25519), you'd be
//   double-hashing (SHA-256 then SHA-512), which is not a real-world
//   pattern. That's why Section 3 explicitly uses ECDSA — to make the
//   'sign-over-hash' framing genuine.
//
// Lesson 3 — Signature sizes vary wildly by algorithm
//   Inspect the lengths of the signatures returned by each section:
//     • Ed25519        →  64 bytes (always)
//     • ECDSA P-256    →  ~70–72 bytes (DER-encoded; ~64 if raw)
//     • RSA-2048       →  256 bytes
//     • RSA-4096       →  512 bytes
//
//   This is why mobile wallets, QR-based credential presentations,
//   NFC mDL transmissions, and SD-JWT compactness all favor Ed25519
//   or ECDSA over RSA. A QR code holding a credential bundle has hard
//   size limits; every signed envelope counts.
