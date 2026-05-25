import {describe, test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, type KeyObject} from 'node:crypto';

import {
    buildOidcAuthorizationUrl,
    mintIdToken,
    verifyIdToken,
} from './oidc.ts';
import {verifyJwsCompact} from '../item2/jwt.ts';

const ISSUER = 'https://issuer.example.com';
const CLIENT_ID = 'wallet-app-42';
const NONCE = 'n-0S6_WzA2Mj';
const NOW = 1_758_000_000;

function freshKeypair(): { publicKey: KeyObject; privateKey: KeyObject } {
    return generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

function standardClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        iss: ISSUER,
        sub: 'user-12345',
        aud: CLIENT_ID,
        exp: NOW + 3600,
        iat: NOW,
        nonce: NONCE,
        ...overrides,
    };
}

const baseExpectations = {
    issuer: ISSUER,
    audience: CLIENT_ID,
    nonce: NONCE,
    now: NOW,
};

describe('Section 1 — mintIdToken', () => {
    test('1a — output is a compact JWS (three "."-separated segments)', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const token = mintIdToken(privateKey, standardClaims());

        // Then
        assert.equal(token.split('.').length, 3);
    });

    test('1b — header is { alg: "ES256", typ: "JWT" }', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();

        // When
        const token = mintIdToken(privateKey, standardClaims());
        const { header } = verifyJwsCompact(token, publicKey, 'ES256');

        // Then
        assert.equal(header.alg, 'ES256');
        assert.equal(header.typ, 'JWT');
    });

    test('1c — payload round-trips the claims object verbatim', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const claims = standardClaims({ custom_claim: 'pass-through' });

        // When
        const token = mintIdToken(privateKey, claims);
        const { payload } = verifyJwsCompact(token, publicKey, 'ES256');

        // Then
        assert.deepEqual(payload, claims);
    });

    test('1d — signature verifies under the matching public key', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();

        // When
        const token = mintIdToken(privateKey, standardClaims());
        const { valid } = verifyJwsCompact(token, publicKey, 'ES256');

        // Then
        assert.equal(valid, true);
    });
});

describe('Section 2 — verifyIdToken', () => {
    test('2a — honestly-minted token with matching expectations is valid', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const token = mintIdToken(privateKey, standardClaims());

        // When
        const result = verifyIdToken(token, publicKey, baseExpectations);

        // Then
        assert.equal(result.valid, true);
        assert.equal(result.reason, undefined);
    });

    test('2b — claims are decoded and returned regardless of validity', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const claims = standardClaims({ iss: 'https://attacker.example.com' });
        const token = mintIdToken(privateKey, claims);

        // When
        const result = verifyIdToken(token, publicKey, baseExpectations);

        // Then
        assert.equal(result.valid, false);
        assert.deepEqual(result.claims, claims);
    });

    test('2c — wrong public key fails with reason "signature"', () => {
        // Given
        const { privateKey } = freshKeypair();
        const { publicKey: unrelatedKey } = freshKeypair();
        const token = mintIdToken(privateKey, standardClaims());

        // When
        const result = verifyIdToken(token, unrelatedKey, baseExpectations);

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'signature');
    });

    test('2d — issuer mismatch fails with reason "iss"', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const token = mintIdToken(privateKey, standardClaims({ iss: 'https://other.example.com' }));

        // When
        const result = verifyIdToken(token, publicKey, baseExpectations);

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'iss');
    });

    test('2e — audience not containing client_id fails with reason "aud"', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const token = mintIdToken(privateKey, standardClaims({ aud: 'some-other-client' }));

        // When
        const result = verifyIdToken(token, publicKey, baseExpectations);

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'aud');
    });

    test('2f — aud as an array containing client_id is accepted', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const token = mintIdToken(privateKey, standardClaims({
            aud: ['some-other-client', CLIENT_ID, 'a-third-one'],
        }));

        // When
        const result = verifyIdToken(token, publicKey, baseExpectations);

        // Then
        assert.equal(result.valid, true);
    });

    test('2g — expired token (exp <= now) fails with reason "exp"', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const token = mintIdToken(privateKey, standardClaims({ exp: NOW - 1 }));

        // When
        const result = verifyIdToken(token, publicKey, baseExpectations);

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'exp');
    });

    test('2h — nonce mismatch fails with reason "nonce"', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const token = mintIdToken(privateKey, standardClaims({ nonce: 'a-different-nonce' }));

        // When
        const result = verifyIdToken(token, publicKey, baseExpectations);

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'nonce');
    });

    test('2i — when expectations.nonce is absent, payload.nonce is not checked', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const token = mintIdToken(privateKey, standardClaims({ nonce: 'something-the-rp-never-sent' }));
        const { nonce, ...expectationsWithoutNonce } = baseExpectations;

        // When
        const result = verifyIdToken(token, publicKey, expectationsWithoutNonce);

        // Then
        assert.equal(result.valid, true);
    });

    test('2j — missing sub fails with reason "sub"', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const { sub, ...claimsWithoutSub } = standardClaims();
        const token = mintIdToken(privateKey, claimsWithoutSub);

        // When
        const result = verifyIdToken(token, publicKey, baseExpectations);

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'sub');
    });
});

describe('Section 3 — buildOidcAuthorizationUrl', () => {
    const authEndpoint = 'https://issuer.example.com/oauth/authorize';
    const sampleParams = {
        clientId: CLIENT_ID,
        redirectUri: 'https://wallet.example.com/callback',
        scope: 'openid email profile',
        state: 'xyz-csrf-abc',
        nonce: NONCE,
        codeChallenge: 'someBase64UrlChallengeValueForTesting',
    };

    test('3a — result preserves authEndpoint origin and pathname', () => {
        // When
        const built = buildOidcAuthorizationUrl(authEndpoint, sampleParams);
        const url = new URL(built);

        // Then
        assert.equal(url.origin, 'https://issuer.example.com');
        assert.equal(url.pathname, '/oauth/authorize');
    });

    test('3b — OAuth-layer params are present (response_type, code_challenge_method, client_id, etc.)', () => {
        // When
        const built = buildOidcAuthorizationUrl(authEndpoint, sampleParams);
        const url = new URL(built);

        // Then
        assert.equal(url.searchParams.get('response_type'), 'code');
        assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
        assert.equal(url.searchParams.get('client_id'), sampleParams.clientId);
        assert.equal(url.searchParams.get('redirect_uri'), sampleParams.redirectUri);
        assert.equal(url.searchParams.get('state'), sampleParams.state);
        assert.equal(url.searchParams.get('code_challenge'), sampleParams.codeChallenge);
    });

    test('3c — scope is carried through verbatim and contains "openid"', () => {
        // When
        const built = buildOidcAuthorizationUrl(authEndpoint, sampleParams);
        const url = new URL(built);

        // Then
        assert.equal(url.searchParams.get('scope'), 'openid email profile');
        assert.ok(url.searchParams.get('scope')!.split(' ').includes('openid'));
    });

    test('3d — nonce is emitted as a top-level query parameter', () => {
        // When
        const built = buildOidcAuthorizationUrl(authEndpoint, sampleParams);
        const url = new URL(built);

        // Then
        assert.equal(url.searchParams.get('nonce'), NONCE);
    });
});

describe('Lesson 1 — `openid` in scope is the trigger', () => {
    test('the wire-format URL surfaces the literal token "openid" inside scope', () => {
        // Given
        const url = new URL(buildOidcAuthorizationUrl('https://op.example/authorize', {
            clientId: 'c', redirectUri: 'https://rp/cb', scope: 'openid email',
            state: 's', nonce: 'n', codeChallenge: 'cc',
        }));

        // Then
        const scopeTokens = url.searchParams.get('scope')!.split(' ');
        assert.ok(scopeTokens.includes('openid'),
            'OIDC is opted into by the literal string "openid" in scope');
    });
});

describe('Lesson 2 — nonce defends the token, state defends the redirect', () => {
    test('a replayed ID Token whose nonce does not match the new session is rejected', () => {
        // Given — issuer mints a token with nonce_A (captured by attacker)
        const { publicKey, privateKey } = freshKeypair();
        const tokenFromOldSession = mintIdToken(privateKey, standardClaims({ nonce: 'nonce_A' }));

        // When — attacker replays the captured token into a new RP session whose nonce is nonce_B
        const newSessionExpectations = { ...baseExpectations, nonce: 'nonce_B' };
        const result = verifyIdToken(tokenFromOldSession, publicKey, newSessionExpectations);

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'nonce');
    });
});

describe('Lesson 3 — ID Token aud must match the verifying client', () => {
    test('a token issued for one client is rejected by another', () => {
        // Given — token aud'd to "client-A"
        const { publicKey, privateKey } = freshKeypair();
        const token = mintIdToken(privateKey, standardClaims({ aud: 'client-A' }));

        // When — "client-B" tries to consume it
        const result = verifyIdToken(token, publicKey, { ...baseExpectations, audience: 'client-B' });

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'aud');
    });
});
