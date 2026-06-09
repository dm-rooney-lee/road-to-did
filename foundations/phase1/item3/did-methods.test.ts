import {describe, test} from 'node:test';
import assert from 'node:assert/strict';

import {
    resolveDidJwk,
    resolveDidKey,
    deriveDidWebUrl,
} from './did-methods.ts';

const DID_CTX_V1 = 'https://www.w3.org/ns/did/v1';
const JWS_2020_CTX = 'https://w3id.org/security/suites/jws-2020/v1';

// ============================================================
// Section 1 — resolveDidJwk
//
// Vectors are base64url(JSON of the JWK). The decoded JWK for each:
//   NO_USE: { crv:'P-256', kty:'EC', x:'tQ12…X', y:'yV56…Y' }
//   SIG:    { crv:'P-256', kty:'EC', x:'SIGx', y:'SIGy', use:'sig' }
//   ENC:    { crv:'P-256', kty:'EC', x:'ENCx', y:'ENCy', use:'enc' }
// ============================================================

const JWK_NO_USE = 'did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6InRRMTIzNGFiY1hZWmV4YW1wbGVYZXhhbXBsZVhleGFtcGxlWGV4YW1wbGVYIiwieSI6InlWNTY3OGRlZlhZWmV4YW1wbGVZZXhhbXBsZVlleGFtcGxlWWV4YW1wbGVZIn0';
const JWK_SIG = 'did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IlNJR3giLCJ5IjoiU0lHeSIsInVzZSI6InNpZyJ9';
const JWK_ENC = 'did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkVOQ3giLCJ5IjoiRU5DeSIsInVzZSI6ImVuYyJ9';

describe('Section 1 — resolveDidJwk', () => {
    test('1a — id and @context are set, with the JWS-2020 context alongside the DID v1 context', () => {
        const doc = resolveDidJwk(JWK_NO_USE);

        assert.equal(doc.id, JWK_NO_USE);
        assert.deepEqual(doc['@context'], [DID_CTX_V1, JWS_2020_CTX]);
    });

    test('1b — the single verification method carries the decoded JWK', () => {
        const doc = resolveDidJwk(JWK_NO_USE);

        assert.equal(doc.verificationMethod?.length, 1);
        const vm = doc.verificationMethod![0];
        assert.equal(vm.id, `${JWK_NO_USE}#0`);
        assert.equal(vm.type, 'JsonWebKey2020');
        assert.equal(vm.controller, JWK_NO_USE);
        assert.deepEqual(vm.publicKeyJwk, {
            crv: 'P-256',
            kty: 'EC',
            x: 'tQ1234abcXYZexampleXexampleXexampleXexampleX',
            y: 'yV5678defXYZexampleYexampleYexampleYexampleY',
        });
    });

    test('1c — a JWK with no "use" gets all five relationships, each referencing #0', () => {
        const doc = resolveDidJwk(JWK_NO_USE);
        const ref = [`${JWK_NO_USE}#0`];

        assert.deepEqual(doc.authentication, ref);
        assert.deepEqual(doc.assertionMethod, ref);
        assert.deepEqual(doc.capabilityInvocation, ref);
        assert.deepEqual(doc.capabilityDelegation, ref);
        assert.deepEqual(doc.keyAgreement, ref);
    });

    test('1d — use:"sig" yields the four signing relationships and no keyAgreement', () => {
        const doc = resolveDidJwk(JWK_SIG);
        const ref = [`${JWK_SIG}#0`];

        assert.deepEqual(doc.authentication, ref);
        assert.deepEqual(doc.assertionMethod, ref);
        assert.deepEqual(doc.capabilityInvocation, ref);
        assert.deepEqual(doc.capabilityDelegation, ref);
        assert.ok(!('keyAgreement' in doc));
    });

    test('1e — use:"enc" yields keyAgreement only', () => {
        const doc = resolveDidJwk(JWK_ENC);
        const ref = [`${JWK_ENC}#0`];

        assert.deepEqual(doc.keyAgreement, ref);
        assert.ok(!('authentication' in doc));
        assert.ok(!('assertionMethod' in doc));
        assert.ok(!('capabilityInvocation' in doc));
        assert.ok(!('capabilityDelegation' in doc));
    });

    test('1f — a non-did:jwk identifier is rejected', () => {
        assert.throws(() => resolveDidJwk('did:web:example.com'));
    });
});

// ============================================================
// Section 2 — resolveDidKey
//
// ED25519 vector encodes raw key bytes [0,1,…,31]; X25519 vector encodes
// raw key bytes [100,101,…,131]. The base64url of those byte runs is the
// expected JWK "x".
// ============================================================

const KEY_ED = 'did:key:z6MkeTGwHmLmuCmgg4ABYhzWVh6ZX7hTwWt8gguAretUfc9c';
const KEY_ED_X = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const KEY_X25519 = 'did:key:z6LSiS5cXwUDnwhcbzi11fAW4iwKxZzrabTvkTMYLr3uB5Pg';
const KEY_X25519_X = 'ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoM';
const KEY_SECP256K1 = 'did:key:zQ3sgm26Cgy2pUboKwkFQgXEdm4gmbTpnVFN8V1QhP6eBiCYf';

describe('Section 2 — resolveDidKey', () => {
    test('2a — id and @context are set', () => {
        const doc = resolveDidKey(KEY_ED);

        assert.equal(doc.id, KEY_ED);
        assert.deepEqual(doc['@context'], [DID_CTX_V1, JWS_2020_CTX]);
    });

    test('2b — an Ed25519 key decodes to an OKP/Ed25519 JWK with the fragment equal to the multibase string', () => {
        const doc = resolveDidKey(KEY_ED);
        const msid = KEY_ED.slice('did:key:'.length);

        const vm = doc.verificationMethod![0];
        assert.equal(vm.id, `${KEY_ED}#${msid}`);
        assert.equal(vm.type, 'JsonWebKey2020');
        assert.equal(vm.controller, KEY_ED);
        assert.deepEqual(vm.publicKeyJwk, {kty: 'OKP', crv: 'Ed25519', x: KEY_ED_X});
    });

    test('2c — an Ed25519 (signing) key gets the four signing relationships and no keyAgreement', () => {
        const doc = resolveDidKey(KEY_ED);
        const ref = [`${KEY_ED}#${KEY_ED.slice('did:key:'.length)}`];

        assert.deepEqual(doc.authentication, ref);
        assert.deepEqual(doc.assertionMethod, ref);
        assert.deepEqual(doc.capabilityInvocation, ref);
        assert.deepEqual(doc.capabilityDelegation, ref);
        assert.ok(!('keyAgreement' in doc));
    });

    test('2d — an X25519 key decodes to an OKP/X25519 JWK', () => {
        const doc = resolveDidKey(KEY_X25519);

        const vm = doc.verificationMethod![0];
        assert.deepEqual(vm.publicKeyJwk, {kty: 'OKP', crv: 'X25519', x: KEY_X25519_X});
    });

    test('2e — an X25519 (agreement) key gets keyAgreement only', () => {
        const doc = resolveDidKey(KEY_X25519);
        const ref = [`${KEY_X25519}#${KEY_X25519.slice('did:key:'.length)}`];

        assert.deepEqual(doc.keyAgreement, ref);
        assert.ok(!('authentication' in doc));
        assert.ok(!('assertionMethod' in doc));
        assert.ok(!('capabilityInvocation' in doc));
        assert.ok(!('capabilityDelegation' in doc));
    });

    test('2f — an unsupported multicodec (secp256k1) is rejected', () => {
        assert.throws(() => resolveDidKey(KEY_SECP256K1));
    });

    test('2g — a non-base58btc multibase is rejected', () => {
        // 'f' is the multibase tag for base16, not base58btc
        assert.throws(() => resolveDidKey('did:key:fABCDEF'));
    });
});

// ============================================================
// Section 3 — deriveDidWebUrl
// ============================================================

describe('Section 3 — deriveDidWebUrl', () => {
    test('3a — a bare domain maps to its /.well-known/did.json', () => {
        assert.equal(
            deriveDidWebUrl('did:web:example.com'),
            'https://example.com/.well-known/did.json',
        );
    });

    test('3b — path segments become URL path components ending in did.json', () => {
        assert.equal(
            deriveDidWebUrl('did:web:example.com:user:alice'),
            'https://example.com/user/alice/did.json',
        );
    });

    test('3c — a percent-encoded port in the authority is decoded, not treated as a separator', () => {
        assert.equal(
            deriveDidWebUrl('did:web:example.com%3A3000:user:alice'),
            'https://example.com:3000/user/alice/did.json',
        );
    });

    test('3d — a bare domain with a port still uses /.well-known/did.json', () => {
        assert.equal(
            deriveDidWebUrl('did:web:localhost%3A8080'),
            'https://localhost:8080/.well-known/did.json',
        );
    });

    test('3e — a non-did:web identifier is rejected', () => {
        assert.throws(() => deriveDidWebUrl('did:key:z6MkABC'));
    });
});
