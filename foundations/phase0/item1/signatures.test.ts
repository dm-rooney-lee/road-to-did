import {describe, test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, hash, sign, verify} from 'node:crypto';

import {hashAndSignWithEcdsaP256, signAndVerifyWithEcdsaP256, signAndVerifyWithEd25519,} from './signatures.ts';

const message = Buffer.from('hello DID');
const tampered = Buffer.from('hello DIE');

describe('Section 1 — Ed25519', () => {
    test('1a — generates an Ed25519 keypair', () => {
        // Given
        // When
        const { publicKey, privateKey } = signAndVerifyWithEd25519(message, tampered);

        // Then
        assert.equal(publicKey.asymmetricKeyType, 'ed25519');
        assert.equal(publicKey.type, 'public');
        assert.equal(privateKey.asymmetricKeyType, 'ed25519');
        assert.equal(privateKey.type, 'private');
    });

    test('1b — signature is a 64-byte Buffer', () => {
        // Given
        // When
        const { signature } = signAndVerifyWithEd25519(message, tampered);

        // Then
        assert.ok(Buffer.isBuffer(signature));
        assert.equal(signature.length, 64);
    });

    test('1c — message signature verifies', () => {
        // Given
        // When
        const { messageValid } = signAndVerifyWithEd25519(message, tampered);

        // Then
        assert.equal(messageValid, true);
    });

    test('1d — tampered message fails verification', () => {
        // Given
        // When
        const { tamperedValid } = signAndVerifyWithEd25519(message, tampered);

        // Then
        assert.equal(tamperedValid, false);
    });
});

describe('Section 2 — ECDSA P-256', () => {
    test('2a — generates an EC keypair on the P-256 curve', () => {
        const { publicKey, privateKey } = signAndVerifyWithEcdsaP256(message);
        assert.equal(publicKey.asymmetricKeyType, 'ec');
        assert.equal(publicKey.type, 'public');
        assert.equal(publicKey.asymmetricKeyDetails?.namedCurve, 'prime256v1');
        assert.equal(privateKey.asymmetricKeyType, 'ec');
        assert.equal(privateKey.type, 'private');
        assert.equal(privateKey.asymmetricKeyDetails?.namedCurve, 'prime256v1');
    });

    test('2b — signature is a non-empty Buffer', () => {
        const { signature } = signAndVerifyWithEcdsaP256(message);
        assert.ok(Buffer.isBuffer(signature));
        assert.ok(signature.length > 0);
    });

    test('2c — signature verifies', () => {
        const { valid } = signAndVerifyWithEcdsaP256(message);
        assert.equal(valid, true);
    });
});

describe('Section 3 — SHA-256 with ECDSA P-256 (ES256 pattern)', () => {
    test('3a — digestHex is 64 lowercase hex characters', () => {
        const { digestHex } = hashAndSignWithEcdsaP256(message);
        assert.equal(typeof digestHex, 'string');
        assert.match(digestHex, /^[0-9a-f]{64}$/);
    });

    test('3b — digestBytes is a 32-byte Buffer', () => {
        const { digestBytes } = hashAndSignWithEcdsaP256(message);
        assert.ok(Buffer.isBuffer(digestBytes));
        assert.equal(digestBytes.length, 32);
    });

    test('3a + 3b — digestHex and digestBytes describe the same hash', () => {
        const { digestHex, digestBytes } = hashAndSignWithEcdsaP256(message);
        assert.equal(digestBytes.toString('hex'), digestHex);
    });

    test('3c — signature is a non-empty Buffer', () => {
        const { signature } = hashAndSignWithEcdsaP256(message);
        assert.ok(Buffer.isBuffer(signature));
        assert.ok(signature.length > 0);
    });

    test('3d — signature verifies', () => {
        const { signatureValid } = hashAndSignWithEcdsaP256(message);
        assert.equal(signatureValid, true);
    });
});

describe('Lesson 1 — Deterministic vs random nonces', () => {
    test('Ed25519 produces the SAME signature for the same (key, message)', () => {
        const { privateKey } = generateKeyPairSync('ed25519');
        const sig1 = sign(null, message, privateKey);
        const sig2 = sign(null, message, privateKey);
        assert.deepEqual(sig1, sig2);
    });

    test('ECDSA produces DIFFERENT signatures for the same (key, message)', () => {
        const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const sig1 = sign('sha256', message, privateKey);
        const sig2 = sign('sha256', message, privateKey);
        assert.notDeepEqual(sig1, sig2);
    });
});

describe('Lesson 2 — Sign over a pre-computed hash', () => {
    test('Signing a digest binds the signature to the digest bytes, not the original message', () => {
        // Genuinely demonstrate the sign-the-digest pattern using Ed25519:
        // we hash the message externally, then pass the digest bytes directly
        // into sign(). The signature is then bound to the digest, not the message.
        //
        // (Ed25519 will internally SHA-512 the digest as part of EdDSA — that's
        // an implementation detail of the algorithm. From our perspective, we
        // signed the digest bytes; verification must use the same digest bytes.)
        const { publicKey, privateKey } = generateKeyPairSync('ed25519');
        const digest = hash('sha256', message, 'buffer');

        const sig = sign(null, digest, privateKey);

        // Verifying against the digest succeeds.
        assert.equal(verify(null, digest, publicKey, sig), true);

        // Verifying against the original message fails — the signature was
        // computed over the digest bytes, not the message bytes.
        assert.equal(verify(null, message, publicKey, sig), false);
    });
});

describe('Lesson 3 — Signature sizes by algorithm', () => {
    test('Ed25519 signature is exactly 64 bytes', () => {
        const { signature } = signAndVerifyWithEd25519(message, tampered);
        assert.equal(signature.length, 64);
    });

    test('ECDSA P-256 signature is 64–72 bytes (DER-encoded)', () => {
        const { signature } = signAndVerifyWithEcdsaP256(message);
        assert.ok(
            signature.length >= 64 && signature.length <= 72,
            `expected 64–72, got ${signature.length}`,
        );
    });

    test('RSA-2048 signature is exactly 256 bytes', () => {
        const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
        const sig = sign('sha256', message, privateKey);
        assert.equal(sig.length, 256);
    });
});
