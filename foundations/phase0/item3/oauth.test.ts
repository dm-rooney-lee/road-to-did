import {describe, test} from 'node:test';
import assert from 'node:assert/strict';

import {
    buildAuthorizationUrl,
    deriveCodeChallenge,
    generatePkceCodeVerifier,
} from './oauth.ts';

// RFC 7636 §B.1 worked example
const RFC_7636_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC_7636_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

const pkceUnreservedPattern = /^[A-Za-z0-9\-._~]+$/;
const base64urlPattern = /^[A-Za-z0-9_-]+$/;

const sampleAuthParams = {
    clientId: 'wallet-app-42',
    redirectUri: 'https://wallet.example.com/callback',
    scope: 'openid VerifiableCredential',
    state: 'xyz-csrf-abc',
    codeChallenge: 'someBase64UrlChallengeValueForTesting',
};
const authEndpoint = 'https://issuer.example.com/oauth/authorize';

describe('Section 1 — generatePkceCodeVerifier', () => {
    test('1a — verifier length is between 43 and 128 characters', () => {
        const verifier = generatePkceCodeVerifier();
        assert.ok(verifier.length >= 43, `expected length ≥ 43, got ${verifier.length}`);
        assert.ok(verifier.length <= 128, `expected length ≤ 128, got ${verifier.length}`);
    });

    test('1b — verifier uses only PKCE-unreserved characters', () => {
        const verifier = generatePkceCodeVerifier();
        assert.match(verifier, pkceUnreservedPattern);
    });

    test('1c — two successive calls return different verifiers', () => {
        const a = generatePkceCodeVerifier();
        const b = generatePkceCodeVerifier();
        assert.notEqual(a, b);
    });
});

describe('Section 2 — deriveCodeChallenge', () => {
    test('2a — RFC 7636 §B.1 worked example matches', () => {
        assert.equal(deriveCodeChallenge(RFC_7636_VERIFIER), RFC_7636_CHALLENGE);
    });

    test('2b — challenge length is exactly 43 characters', () => {
        const challenge = deriveCodeChallenge(generatePkceCodeVerifier());
        assert.equal(challenge.length, 43);
    });

    test('2c — challenge uses only base64url characters', () => {
        const challenge = deriveCodeChallenge(generatePkceCodeVerifier());
        assert.match(challenge, base64urlPattern);
    });

    test('2d — same verifier always yields the same challenge', () => {
        const verifier = generatePkceCodeVerifier();
        assert.equal(deriveCodeChallenge(verifier), deriveCodeChallenge(verifier));
    });
});

describe('Section 3 — buildAuthorizationUrl', () => {
    test('3a — result preserves authEndpoint origin and pathname', () => {
        const built = buildAuthorizationUrl(authEndpoint, sampleAuthParams);
        const url = new URL(built);
        assert.equal(url.origin, 'https://issuer.example.com');
        assert.equal(url.pathname, '/oauth/authorize');
    });

    test('3b — response_type=code is set', () => {
        const built = buildAuthorizationUrl(authEndpoint, sampleAuthParams);
        const url = new URL(built);
        assert.equal(url.searchParams.get('response_type'), 'code');
    });

    test('3c — code_challenge_method=S256 is set', () => {
        const built = buildAuthorizationUrl(authEndpoint, sampleAuthParams);
        const url = new URL(built);
        assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    });

    test('3d — camelCase inputs become snake_case query params with the same values', () => {
        const built = buildAuthorizationUrl(authEndpoint, sampleAuthParams);
        const url = new URL(built);
        assert.equal(url.searchParams.get('client_id'),      sampleAuthParams.clientId);
        assert.equal(url.searchParams.get('redirect_uri'),   sampleAuthParams.redirectUri);
        assert.equal(url.searchParams.get('scope'),          sampleAuthParams.scope);
        assert.equal(url.searchParams.get('state'),          sampleAuthParams.state);
        assert.equal(url.searchParams.get('code_challenge'), sampleAuthParams.codeChallenge);
    });
});

describe('Lesson 1 — Challenge length is constant regardless of verifier length', () => {
    test('SHA-256 collapses any-length verifier to 32 bytes → 43 base64url chars', () => {
        const short = 'a'.repeat(43);
        const long  = 'a'.repeat(128);
        assert.equal(deriveCodeChallenge(short).length, 43);
        assert.equal(deriveCodeChallenge(long).length,  43);
    });
});

describe('Lesson 2 — OAuth wire-format parameter names are snake_case', () => {
    test('no camelCase parameter keys appear in the URL', () => {
        const built = buildAuthorizationUrl(authEndpoint, sampleAuthParams);
        const url = new URL(built);
        for (const camelCaseName of [
            'clientId',
            'redirectUri',
            'codeChallenge',
            'codeChallengeMethod',
            'responseType',
        ]) {
            assert.equal(
                url.searchParams.get(camelCaseName),
                null,
                `unexpected camelCase param "${camelCaseName}" found in URL`,
            );
        }
    });
});

describe('Lesson 3 — Verifier → challenge is one-way', () => {
    test('different verifiers produce different challenges', () => {
        const challengeA = deriveCodeChallenge(generatePkceCodeVerifier());
        const challengeB = deriveCodeChallenge(generatePkceCodeVerifier());
        assert.notEqual(challengeA, challengeB);
    });
});
