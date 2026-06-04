import {describe, test} from 'node:test';
import assert from 'node:assert/strict';

import {
    parseDidUrl,
    buildDidDocument,
    dereferenceVerificationMethod,
    type VerificationMethod,
    type DidDocument,
} from './did.ts';

const DID_CTX_V1 = 'https://www.w3.org/ns/did/v1';
const DID = 'did:example:123456789abcdefghi';

const KEY_1: VerificationMethod = {
    id: `${DID}#key-1`,
    type: 'JsonWebKey2020',
    controller: DID,
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'aaa', y: 'bbb' },
};

const KEY_2: VerificationMethod = {
    id: `${DID}#key-2`,
    type: 'JsonWebKey2020',
    controller: DID,
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'ccc', y: 'ddd' },
};

// ============================================================
// Section 1 — parseDidUrl
// ============================================================

describe('Section 1 — parseDidUrl', () => {
    test('1a — a bare DID yields method and methodSpecificId, no path/query/fragment', () => {
        const parts = parseDidUrl('did:example:123456');

        assert.equal(parts.did, 'did:example:123456');
        assert.equal(parts.method, 'example');
        assert.equal(parts.methodSpecificId, '123456');
        assert.equal(parts.path, undefined);
        assert.equal(parts.query, undefined);
        assert.equal(parts.fragment, undefined);
    });

    test('1b — a method-specific-id may itself contain ":" segments', () => {
        const parts = parseDidUrl('did:web:example.com:user:alice');

        assert.equal(parts.method, 'web');
        assert.equal(parts.methodSpecificId, 'example.com:user:alice');
        assert.equal(parts.did, 'did:web:example.com:user:alice');
    });

    test('1c — a fragment is split off and returned without the "#"', () => {
        const parts = parseDidUrl('did:example:123#key-1');

        assert.equal(parts.did, 'did:example:123');
        assert.equal(parts.fragment, 'key-1');
        assert.equal(parts.path, undefined);
        assert.equal(parts.query, undefined);
    });

    test('1d — a query is split off and returned without the "?"', () => {
        const parts = parseDidUrl('did:example:123?service=files');

        assert.equal(parts.did, 'did:example:123');
        assert.equal(parts.query, 'service=files');
        assert.equal(parts.fragment, undefined);
    });

    test('1e — a path is split off and returned WITH its leading "/"', () => {
        const parts = parseDidUrl('did:example:123/path/to/res');

        assert.equal(parts.did, 'did:example:123');
        assert.equal(parts.path, '/path/to/res');
    });

    test('1f — path, query, and fragment together split at the right boundaries', () => {
        const parts = parseDidUrl('did:example:123/a/b?x=1&y=2#frag');

        assert.equal(parts.did, 'did:example:123');
        assert.equal(parts.path, '/a/b');
        assert.equal(parts.query, 'x=1&y=2');
        assert.equal(parts.fragment, 'frag');
    });

    test('1g — a "#" inside the query region does not start until after the query', () => {
        // query runs up to the fragment; the first "#" begins the fragment
        const parts = parseDidUrl('did:example:123?a=1#b=2');

        assert.equal(parts.query, 'a=1');
        assert.equal(parts.fragment, 'b=2');
    });

    test('1h — missing "did:" scheme is rejected', () => {
        assert.throws(() => parseDidUrl('example:123'));
    });

    test('1i — an empty method-name is rejected', () => {
        assert.throws(() => parseDidUrl('did::123'));
    });

    test('1j — an uppercase method-name is rejected (method-name is lowercase only)', () => {
        assert.throws(() => parseDidUrl('did:Example:123'));
    });

    test('1k — an empty method-specific-id is rejected', () => {
        assert.throws(() => parseDidUrl('did:example:'));
    });

    test('1l — a method-specific-id with an illegal character is rejected', () => {
        // space is not an idchar
        assert.throws(() => parseDidUrl('did:example:abc def'));
    });

    test('1m — a "/" inside the query does not create a path (path stays undefined)', () => {
        // the "/" in relativeRef belongs to the query, not a path component;
        // path is present only when the URL actually has a path segment
        const parts = parseDidUrl('did:example:123?service=files&relativeRef=/img');

        assert.equal(parts.did, 'did:example:123');
        assert.equal(parts.query, 'service=files&relativeRef=/img');
        assert.equal(parts.path, undefined);
        assert.equal(parts.fragment, undefined);
    });

    test('1n — a "?" inside the fragment stays part of the fragment (no phantom query)', () => {
        // the fragment runs to the end of the string; a "?" after "#" is fragment text,
        // not a query introducer
        const parts = parseDidUrl('did:example:123#frag?x=1');

        assert.equal(parts.did, 'did:example:123');
        assert.equal(parts.fragment, 'frag?x=1');
        assert.equal(parts.query, undefined);
        assert.equal(parts.path, undefined);
    });
});

// ============================================================
// Section 2 — buildDidDocument
// ============================================================

describe('Section 2 — buildDidDocument', () => {
    test('2a — id equals the input DID', () => {
        const doc = buildDidDocument({
            '@context': [DID_CTX_V1],
            did: DID,
            verificationMethods: [KEY_1],
        });

        assert.equal(doc.id, DID);
    });

    test('2b — @context passes through verbatim', () => {
        const doc = buildDidDocument({
            '@context': [DID_CTX_V1],
            did: DID,
            verificationMethods: [KEY_1],
        });

        assert.deepEqual(doc['@context'], [DID_CTX_V1]);
    });

    test('2c — verificationMethod carries the supplied methods', () => {
        const doc = buildDidDocument({
            '@context': [DID_CTX_V1],
            did: DID,
            verificationMethods: [KEY_1, KEY_2],
        });

        assert.deepEqual(doc.verificationMethod, [KEY_1, KEY_2]);
    });

    test('2d — a supplied relationship becomes an array of reference strings, not embedded objects', () => {
        const doc = buildDidDocument({
            '@context': [DID_CTX_V1],
            did: DID,
            verificationMethods: [KEY_1],
            assertionMethod: [KEY_1.id],
        });

        assert.deepEqual(doc.assertionMethod, [KEY_1.id]);
    });

    test('2e — relationships not supplied are omitted entirely', () => {
        const doc = buildDidDocument({
            '@context': [DID_CTX_V1],
            did: DID,
            verificationMethods: [KEY_1],
            assertionMethod: [KEY_1.id],
        });

        assert.ok(!('authentication' in doc));
        assert.ok(!('keyAgreement' in doc));
    });

    test('2f — two relationships can reference the same key', () => {
        const doc = buildDidDocument({
            '@context': [DID_CTX_V1],
            did: DID,
            verificationMethods: [KEY_1],
            authentication: [KEY_1.id],
            assertionMethod: [KEY_1.id],
        });

        assert.deepEqual(doc.authentication, [KEY_1.id]);
        assert.deepEqual(doc.assertionMethod, [KEY_1.id]);
    });

    test('2g — a relationship referencing an undefined verification method id is rejected', () => {
        assert.throws(() => buildDidDocument({
            '@context': [DID_CTX_V1],
            did: DID,
            verificationMethods: [KEY_1],
            assertionMethod: [`${DID}#key-does-not-exist`],
        }));
    });
});

// ============================================================
// Section 3 — dereferenceVerificationMethod
// ============================================================

describe('Section 3 — dereferenceVerificationMethod', () => {
    function docWith(overrides: Partial<DidDocument> = {}): DidDocument {
        return {
            '@context': [DID_CTX_V1],
            id: DID,
            verificationMethod: [KEY_1, KEY_2],
            assertionMethod: [KEY_1.id],
            ...overrides,
        };
    }

    test('3a — a reference matching a verificationMethod entry returns that method', () => {
        const vm = dereferenceVerificationMethod(docWith(), KEY_1.id);

        assert.deepEqual(vm, KEY_1);
    });

    test('3b — the correct method is selected when several are present', () => {
        const vm = dereferenceVerificationMethod(docWith(), KEY_2.id);

        assert.deepEqual(vm, KEY_2);
    });

    test('3c — a reference whose bare DID differs from the document id returns null', () => {
        // same fragment, different DID — this document cannot speak for it
        const vm = dereferenceVerificationMethod(docWith(), 'did:example:OTHER#key-1');

        assert.equal(vm, null);
    });

    test('3d — a fragment with no matching method returns null', () => {
        const vm = dereferenceVerificationMethod(docWith(), `${DID}#key-absent`);

        assert.equal(vm, null);
    });

    test('3e — an embedded method inside a relationship array is found', () => {
        const embedded: VerificationMethod = {
            id: `${DID}#embedded-1`,
            type: 'JsonWebKey2020',
            controller: DID,
            publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'eee', y: 'fff' },
        };
        const doc = docWith({
            verificationMethod: [KEY_1],
            authentication: [embedded],
        });

        const vm = dereferenceVerificationMethod(doc, embedded.id);

        assert.deepEqual(vm, embedded);
    });

    test('3f — a string reference inside a relationship is resolved via verificationMethod, not treated as embedded', () => {
        // KEY_2 is referenced by string under assertionMethod and defined under
        // verificationMethod; dereferencing its id must return the full object
        const doc = docWith({ assertionMethod: [KEY_2.id] });

        const vm = dereferenceVerificationMethod(doc, KEY_2.id);

        assert.deepEqual(vm, KEY_2);
    });
});
