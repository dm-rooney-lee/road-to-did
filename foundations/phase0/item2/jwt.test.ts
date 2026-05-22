import {describe, test} from 'node:test';
import assert from 'node:assert/strict';
import {createPublicKey, generateKeyPairSync, type KeyObject, sign} from 'node:crypto';

import {encodeJwsCompact, exportPublicJwk, verifyJwsCompact} from './jwt.ts';

const header = { alg: 'ES256' as const, typ: 'JWT' as const };
const payload = {
    iss: 'did:example:issuer',
    sub: 'did:example:subject',
    iat: 1700000000,
    exp: 1700003600,
};
const base64urlPattern = /^[A-Za-z0-9_-]+$/;

function freshKeypair(): { publicKey: KeyObject; privateKey: KeyObject } {
    return generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

describe('Section 1 — encodeJwsCompact (ES256)', () => {
    test('1a — token is three base64url segments joined by "."', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const { token } = encodeJwsCompact(header, payload, privateKey);

        // Then
        const parts = token.split('.');
        assert.equal(parts.length, 3);
        for (const part of parts) {
            assert.match(part, base64urlPattern, `segment is not base64url: "${part}"`);
        }
    });

    test('1b — encodedHeader decodes back to the input header JSON', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const { encodedHeader } = encodeJwsCompact(header, payload, privateKey);

        // Then
        const decoded = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
        assert.deepEqual(decoded, header);
    });

    test('1c — encodedPayload decodes back to the input payload JSON', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const { encodedPayload } = encodeJwsCompact(header, payload, privateKey);

        // Then
        const decoded = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
        assert.deepEqual(decoded, payload);
    });

    test('1d — signatureBytes is exactly 64 bytes (raw R‖S, not DER)', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const { signatureBytes } = encodeJwsCompact(header, payload, privateKey);

        // Then
        assert.ok(Buffer.isBuffer(signatureBytes));
        assert.equal(signatureBytes.length, 64);
    });

    test('1e — token reconstructs from the three encoded parts', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const { encodedHeader, encodedPayload, encodedSignature, token } =
            encodeJwsCompact(header, payload, privateKey);

        // Then
        assert.equal(token, `${encodedHeader}.${encodedPayload}.${encodedSignature}`);
    });
});

describe('Section 2 — verifyJwsCompact (ES256)', () => {
    test('2a — honestly-signed token verifies', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const { token } = encodeJwsCompact(header, payload, privateKey);

        // When
        const { valid } = verifyJwsCompact(token, publicKey, 'ES256');

        // Then
        assert.equal(valid, true);
    });

    test('2b — header and payload are decoded to match the originals', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const { token } = encodeJwsCompact(header, payload, privateKey);

        // When
        const result = verifyJwsCompact(token, publicKey, 'ES256');

        // Then
        assert.deepEqual(result.header, header);
        assert.deepEqual(result.payload, payload);
    });

    test('2c — tampering the payload invalidates the signature', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const { token } = encodeJwsCompact(header, payload, privateKey);
        const [encodedHeader, _, encodedSignature] = token.split('.');
        const tamperedPayload = Buffer.from(
            JSON.stringify({ ...payload, sub: 'did:example:attacker' }),
        ).toString('base64url');
        const forged = `${encodedHeader}.${tamperedPayload}.${encodedSignature}`;

        // When
        const { valid } = verifyJwsCompact(forged, publicKey, 'ES256');

        // Then
        assert.equal(valid, false);
    });

    test('2d — verifying with a different public key fails', () => {
        // Given
        const { privateKey } = freshKeypair();
        const { publicKey: otherPublicKey } = freshKeypair();
        const { token } = encodeJwsCompact(header, payload, privateKey);

        // When
        const { valid } = verifyJwsCompact(token, otherPublicKey, 'ES256');

        // Then
        assert.equal(valid, false);
    });
});

describe('Section 3 — exportPublicJwk (EC P-256)', () => {
    test('3a — kty is "EC" and crv is "P-256"', () => {
        // Given
        const { publicKey } = freshKeypair();

        // When
        const jwk = exportPublicJwk(publicKey);

        // Then
        assert.equal(jwk.kty, 'EC');
        assert.equal(jwk.crv, 'P-256');
    });

    test('3b — x and y are base64url-encoded 32-byte coordinates', () => {
        // Given
        const { publicKey } = freshKeypair();

        // When
        const jwk = exportPublicJwk(publicKey);

        // Then
        assert.match(jwk.x, base64urlPattern);
        assert.match(jwk.y, base64urlPattern);
        assert.equal(Buffer.from(jwk.x, 'base64url').length, 32);
        assert.equal(Buffer.from(jwk.y, 'base64url').length, 32);
    });

    test('3c — re-importing the JWK yields a key that verifies the original signer', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();

        // When
        const jwk = exportPublicJwk(publicKey);
        const reimported = createPublicKey({ key: jwk, format: 'jwk' });
        const { token } = encodeJwsCompact(header, payload, privateKey);
        const { valid } = verifyJwsCompact(token, reimported, 'ES256');

        // Then
        assert.equal(valid, true);
    });
});

describe('Lesson 1 — base64url has no padding and is URL-safe', () => {
    test('encoding/decoding round-trips and the output contains no "=", "+", or "/"', () => {
        const random = Buffer.from(
            'binary bytes that would need + and / in standard base64: ??>>',
        );

        const encoded = random.toString('base64url');

        assert.ok(!encoded.includes('='), 'base64url must not contain padding');
        assert.ok(!encoded.includes('+'), 'base64url must use "-" instead of "+"');
        assert.ok(!encoded.includes('/'), 'base64url must use "_" instead of "/"');
        assert.deepEqual(Buffer.from(encoded, 'base64url'), random);
    });
});

describe('Lesson 2 — The "alg: none" attack', () => {
    test('a token with header.alg = "none" and an empty signature is rejected', () => {
        // Given
        const { publicKey } = freshKeypair();
        const attackerHeader = Buffer.from(
            JSON.stringify({ alg: 'none', typ: 'JWT' }),
        ).toString('base64url');
        const attackerPayload = Buffer.from(
            JSON.stringify({ iss: 'attacker', sub: 'admin' }),
        ).toString('base64url');
        const attackerToken = `${attackerHeader}.${attackerPayload}.`;

        // When
        const { valid } = verifyJwsCompact(attackerToken, publicKey, 'ES256');

        // Then
        assert.equal(valid, false);
    });
});

describe('Lesson 3 — ECDSA signature format: DER vs JOSE raw', () => {
    const message = Buffer.from('any message');

    test('Node default ECDSA signature is DER-encoded (64–72 bytes, variable)', () => {
        const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

        const der = sign('sha256', message, privateKey);

        assert.ok(
            der.length >= 64 && der.length <= 72,
            `expected DER signature 64–72 bytes, got ${der.length}`,
        );
    });

    test('with dsaEncoding "ieee-p1363" the signature is exactly 64 bytes (JOSE form)', () => {
        const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

        const raw = sign('sha256', message, { key: privateKey, dsaEncoding: 'ieee-p1363' });

        assert.equal(raw.length, 64);
    });
});
