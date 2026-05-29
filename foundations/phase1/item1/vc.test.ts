import {describe, test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, type KeyObject} from 'node:crypto';

import {
    buildVerifiableCredential,
    signCredentialAsVcJwt,
    verifyVcJwt,
    type VerifiableCredential,
} from './vc.ts';
import {encodeJwsCompact, verifyJwsCompact} from '../../phase0/item2/jwt.ts';

const ISSUER_DID  = 'did:example:issuer';
const SUBJECT_DID = 'did:example:alice';
const VC_CTX_V2   = 'https://www.w3.org/ns/credentials/v2';

// 2026-01-01T00:00:00Z and 2027-01-01T00:00:00Z, expressed both ways
const VALID_FROM_ISO   = '2026-01-01T00:00:00.000Z';
const VALID_UNTIL_ISO  = '2027-01-01T00:00:00.000Z';
const VALID_FROM_UNIX  = Math.floor(Date.parse(VALID_FROM_ISO)  / 1000);
const VALID_UNTIL_UNIX = Math.floor(Date.parse(VALID_UNTIL_ISO) / 1000);
const NOW              = VALID_FROM_UNIX + 60;   // one minute after validFrom

function freshKeypair(): { publicKey: KeyObject; privateKey: KeyObject } {
    return generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

const sampleClaims = {
    name: 'Alice',
    degreeType: 'BachelorDegree',
    issuingInstitution: 'Example University',
};

function sampleInput(overrides: Partial<Parameters<typeof buildVerifiableCredential>[0]> = {}) {
    return {
        issuer: ISSUER_DID,
        subject: SUBJECT_DID,
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        '@context': [VC_CTX_V2],
        claims: sampleClaims,
        validFrom: VALID_FROM_ISO,
        validUntil: VALID_UNTIL_ISO,
        ...overrides,
    };
}

// ============================================================
// Section 1 — buildVerifiableCredential
// ============================================================

describe('Section 1 — buildVerifiableCredential', () => {
    test('1a — @context array starts with the W3C VC v2 context', () => {
        // When
        const vc = buildVerifiableCredential(sampleInput());

        // Then
        assert.ok(Array.isArray(vc['@context']));
        assert.equal(vc['@context'][0], VC_CTX_V2);
    });

    test('1b — type array contains "VerifiableCredential"', () => {
        // When
        const vc = buildVerifiableCredential(sampleInput());

        // Then
        assert.ok(vc.type.includes('VerifiableCredential'));
    });

    test('1c — types passed in input.type appear in output.type verbatim', () => {
        // When
        const vc = buildVerifiableCredential(sampleInput({
            type: ['VerifiableCredential', 'UniversityDegreeCredential', 'AccreditedCredential'],
        }));

        // Then
        assert.deepEqual(vc.type, ['VerifiableCredential', 'UniversityDegreeCredential', 'AccreditedCredential']);
    });

    test('1e — input.id passes through verbatim', () => {
        // Given
        const id = 'urn:uuid:11111111-2222-3333-4444-555555555555';

        // When
        const vc = buildVerifiableCredential(sampleInput({ id }));

        // Then
        assert.equal(vc.id, id);
    });

    test('1f — when input.id is absent, id is auto-generated as a urn:uuid', () => {
        // When
        const vc = buildVerifiableCredential(sampleInput({ id: undefined }));

        // Then — function auto-generates a URN UUID. See Section 1 contract
        // for why this one field breaks the "trust the caller" pattern.
        assert.ok(vc.id, 'expected an auto-generated id');
        assert.match(vc.id!, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    });

    test('1g — issuer field matches input.issuer', () => {
        // When
        const vc = buildVerifiableCredential(sampleInput());

        // Then
        assert.equal(vc.issuer, ISSUER_DID);
    });

    test('1h — credentialSubject.id matches input.subject', () => {
        // When
        const vc = buildVerifiableCredential(sampleInput());

        // Then
        assert.equal(vc.credentialSubject.id, SUBJECT_DID);
    });

    test('1i — credentialSubject contains the input claims', () => {
        // When
        const vc = buildVerifiableCredential(sampleInput());

        // Then
        for (const [k, v] of Object.entries(sampleClaims)) {
            assert.equal(vc.credentialSubject[k], v, `expected credentialSubject.${k} = ${v}`);
        }
    });

    test('1j — validFrom and validUntil pass through verbatim as ISO 8601 strings', () => {
        // When
        const vc = buildVerifiableCredential(sampleInput());

        // Then
        assert.equal(vc.validFrom,  VALID_FROM_ISO);
        assert.equal(vc.validUntil, VALID_UNTIL_ISO);
    });

    test('1k — input["@context"] passes through verbatim, including extension vocabularies', () => {
        // Given
        const ctx = [
            VC_CTX_V2,
            'https://www.w3.org/2018/credentials/examples/v1',
            'https://schema.org',
        ];

        // When
        const vc = buildVerifiableCredential(sampleInput({ '@context': ctx }));

        // Then — @context array passes through exactly as supplied
        assert.deepEqual(vc['@context'], ctx);
    });
});

// ============================================================
// Section 2 — signCredentialAsVcJwt
// ============================================================

describe('Section 2 — signCredentialAsVcJwt', () => {
    function freshVc(overrides: Partial<Parameters<typeof buildVerifiableCredential>[0]> = {}): VerifiableCredential {
        return buildVerifiableCredential(sampleInput(overrides));
    }

    test('2a — output is a compact JWS (three "."-separated segments)', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const vcJwt = signCredentialAsVcJwt(freshVc(), privateKey);

        // Then
        assert.equal(vcJwt.split('.').length, 3);
    });

    test('2b — header is { alg: "ES256", typ: "JWT" }', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();

        // When
        const vcJwt = signCredentialAsVcJwt(freshVc(), privateKey);
        const { header } = verifyJwsCompact(vcJwt, publicKey, 'ES256');

        // Then
        assert.equal(header.alg, 'ES256');
        assert.equal(header.typ, 'JWT');
    });

    test('2c — payload.iss === credential.issuer', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const vc = freshVc();

        // When
        const vcJwt = signCredentialAsVcJwt(vc, privateKey);
        const { payload } = verifyJwsCompact(vcJwt, publicKey, 'ES256');

        // Then
        assert.equal(payload.iss, vc.issuer);
    });

    test('2d — payload.sub === credential.credentialSubject.id', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const vc = freshVc();

        // When
        const vcJwt = signCredentialAsVcJwt(vc, privateKey);
        const { payload } = verifyJwsCompact(vcJwt, publicKey, 'ES256');

        // Then
        assert.equal(payload.sub, vc.credentialSubject.id);
    });

    test('2e — payload.vc deeply equals the input credential', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const vc = freshVc();

        // When
        const vcJwt = signCredentialAsVcJwt(vc, privateKey);
        const { payload } = verifyJwsCompact(vcJwt, publicKey, 'ES256');

        // Then
        assert.deepEqual(payload.vc, vc);
    });

    test('2f — payload.nbf === Unix seconds of validFrom', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();

        // When
        const vcJwt = signCredentialAsVcJwt(freshVc(), privateKey);
        const { payload } = verifyJwsCompact(vcJwt, publicKey, 'ES256');

        // Then
        assert.equal(payload.nbf, VALID_FROM_UNIX);
    });

    test('2g — payload.exp === Unix seconds of validUntil', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();

        // When
        const vcJwt = signCredentialAsVcJwt(freshVc(), privateKey);
        const { payload } = verifyJwsCompact(vcJwt, publicKey, 'ES256');

        // Then
        assert.equal(payload.exp, VALID_UNTIL_UNIX);
    });

    test('2h — payload.jti matches credential.id when the credential carries one', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const id = 'urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

        // When
        const vcJwt = signCredentialAsVcJwt(freshVc({ id }), privateKey);
        const { payload } = verifyJwsCompact(vcJwt, publicKey, 'ES256');

        // Then
        assert.equal(payload.jti, id);
    });

    test('2i — signature verifies under the issuer\'s public key', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();

        // When
        const vcJwt = signCredentialAsVcJwt(freshVc(), privateKey);
        const { valid } = verifyJwsCompact(vcJwt, publicKey, 'ES256');

        // Then
        assert.equal(valid, true);
    });
});

// ============================================================
// Section 3 — verifyVcJwt
// ============================================================

describe('Section 3 — verifyVcJwt', () => {
    function freshVcJwt(overrides: Partial<Parameters<typeof buildVerifiableCredential>[0]> = {}) {
        const { publicKey, privateKey } = freshKeypair();
        const vc = buildVerifiableCredential(sampleInput(overrides));
        const vcJwt = signCredentialAsVcJwt(vc, privateKey);
        return { publicKey, privateKey, vc, vcJwt };
    }

    test('3a — honestly-issued VC-JWT is valid under the issuer\'s public key', () => {
        // Given
        const { publicKey, vcJwt } = freshVcJwt();

        // When
        const result = verifyVcJwt(vcJwt, publicKey, { expectedIssuer: ISSUER_DID, now: NOW });

        // Then
        assert.equal(result.valid, true);
        assert.equal(result.reason, undefined);
    });

    test('3b — the embedded credential is returned and matches the original', () => {
        // Given
        const { publicKey, vc, vcJwt } = freshVcJwt();

        // When
        const result = verifyVcJwt(vcJwt, publicKey, { expectedIssuer: ISSUER_DID, now: NOW });

        // Then
        assert.deepEqual(result.credential, vc);
    });

    test('3c — wrong public key fails with reason "signature"', () => {
        // Given
        const { vcJwt } = freshVcJwt();
        const { publicKey: unrelatedKey } = freshKeypair();

        // When
        const result = verifyVcJwt(vcJwt, unrelatedKey, { expectedIssuer: ISSUER_DID, now: NOW });

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'signature');
    });

    test('3d — issuer mismatch fails with reason "iss"', () => {
        // Given
        const { publicKey, vcJwt } = freshVcJwt();

        // When
        const result = verifyVcJwt(vcJwt, publicKey, { expectedIssuer: 'did:example:someone-else', now: NOW });

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'iss');
    });

    test('3e — when expectedIssuer is omitted, iss is not checked', () => {
        // Given
        const { publicKey, vcJwt } = freshVcJwt();

        // When
        const result = verifyVcJwt(vcJwt, publicKey, { now: NOW });

        // Then
        assert.equal(result.valid, true);
    });

    test('3f — expired credential (now >= exp) fails with reason "exp"', () => {
        // Given
        const { publicKey, vcJwt } = freshVcJwt();
        const wellAfterExpiry = VALID_UNTIL_UNIX + 1;

        // When
        const result = verifyVcJwt(vcJwt, publicKey, { expectedIssuer: ISSUER_DID, now: wellAfterExpiry });

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'exp');
    });

    test('3g — payload without a "vc" claim fails with reason "vc"', () => {
        // Given — sign a JWT that has the right shape EXCEPT no vc claim
        const { publicKey, privateKey } = freshKeypair();
        const { token } = encodeJwsCompact(
            { alg: 'ES256' as const, typ: 'JWT' as const },
            { iss: ISSUER_DID, sub: SUBJECT_DID /* no vc */ },
            privateKey,
        );

        // When
        const result = verifyVcJwt(token, publicKey, { expectedIssuer: ISSUER_DID, now: NOW });

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'vc');
    });

    test('3h — embedded credential missing @context fails with reason "vc"', () => {
        // Given — vc claim has no @context at all
        const { publicKey, privateKey } = freshKeypair();
        const malformedVc = {
            // no @context
            id: 'urn:uuid:11111111-2222-3333-4444-555555555555',
            type: ['VerifiableCredential'],
            issuer: ISSUER_DID,
            credentialSubject: { id: SUBJECT_DID },
        };
        const { token } = encodeJwsCompact(
            { alg: 'ES256' as const, typ: 'JWT' as const },
            { iss: ISSUER_DID, sub: SUBJECT_DID, vc: malformedVc },
            privateKey,
        );

        // When
        const result = verifyVcJwt(token, publicKey, { expectedIssuer: ISSUER_DID, now: NOW });

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'vc');
    });

    test('3i — embedded credential whose @context[0] is not the VCDM 2.0 context fails with reason "vc"', () => {
        // Given — credential carries the VCDM 1.x context instead of v2
        const { publicKey, privateKey } = freshKeypair();
        const vcWithWrongContext = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],   // 1.x, not v2
            id: 'urn:uuid:11111111-2222-3333-4444-555555555555',
            type: ['VerifiableCredential'],
            issuer: ISSUER_DID,
            credentialSubject: { id: SUBJECT_DID },
        };
        const { token } = encodeJwsCompact(
            { alg: 'ES256' as const, typ: 'JWT' as const },
            { iss: ISSUER_DID, sub: SUBJECT_DID, vc: vcWithWrongContext },
            privateKey,
        );

        // When
        const result = verifyVcJwt(token, publicKey, { expectedIssuer: ISSUER_DID, now: NOW });

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'vc');
    });

    test('3j — payload.iss differing from payload.vc.issuer fails with reason "vc-iss"', () => {
        // Given — payload.iss claims "did:example:attacker"; the embedded vc.issuer
        // claims ISSUER_DID. A well-formed credential would have both agree.
        const { publicKey, privateKey } = freshKeypair();
        const honestVc = buildVerifiableCredential(sampleInput());   // vc.issuer = ISSUER_DID
        const { token } = encodeJwsCompact(
            { alg: 'ES256' as const, typ: 'JWT' as const },
            {
                iss: 'did:example:attacker',     // ← doesn't match vc.issuer
                sub: SUBJECT_DID,
                vc: honestVc,
            },
            privateKey,
        );

        // When — verifier expects "did:example:attacker" so the iss check PASSES,
        // letting the run reach the vc-iss step. The vc-iss step is what catches it.
        const result = verifyVcJwt(token, publicKey, {
            expectedIssuer: 'did:example:attacker',
            now: NOW,
        });

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'vc-iss');
    });

    test('3k — a bad signature on a token with no vc claim reports "signature", not "vc"', () => {
        // Given — a token with NO vc claim, verified under the WRONG key. Both
        // the signature check (1) and the vc check (4) would fail; the contract's
        // check order requires the FIRST failure in order — signature — to win.
        const { privateKey } = freshKeypair();
        const { publicKey: unrelatedKey } = freshKeypair();
        const { token } = encodeJwsCompact(
            { alg: 'ES256' as const, typ: 'JWT' as const },
            { iss: ISSUER_DID, sub: SUBJECT_DID /* no vc */ },
            privateKey,
        );

        // When
        const result = verifyVcJwt(token, unrelatedKey, { expectedIssuer: ISSUER_DID, now: NOW });

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'signature');
    });

    test('3l — a type array containing "VerifiableCredential" out of first position is still valid', () => {
        // Given — "VerifiableCredential" is present but not at index 0. The
        // contract requires type to CONTAIN it, not to lead with it. (Contrast
        // with @context, where position 0 IS significant.)
        const { publicKey, vcJwt } = freshVcJwt({
            type: ['UniversityDegreeCredential', 'VerifiableCredential'],
        });

        // When
        const result = verifyVcJwt(vcJwt, publicKey, { expectedIssuer: ISSUER_DID, now: NOW });

        // Then
        assert.equal(result.valid, true);
        assert.equal(result.reason, undefined);
    });

    test('3m — a vc claim that is null fails with reason "vc" and returns {} as credential', () => {
        // Given — vc present but null: not a usable credential object. The
        // credential field must collapse to {} (a Record, never null).
        const { publicKey, privateKey } = freshKeypair();
        const { token } = encodeJwsCompact(
            { alg: 'ES256' as const, typ: 'JWT' as const },
            { iss: ISSUER_DID, sub: SUBJECT_DID, vc: null },
            privateKey,
        );

        // When
        const result = verifyVcJwt(token, publicKey, { expectedIssuer: ISSUER_DID, now: NOW });

        // Then
        assert.equal(result.valid, false);
        assert.equal(result.reason, 'vc');
        assert.deepEqual(result.credential, {});
    });
});

// ============================================================
// Lessons
// ============================================================

describe('Lesson 1 — Issuer signs; verifier checks with the issuer\'s public key only', () => {
    test('the verifier never needs the private key, only the public key', () => {
        // Given — issuer mints a credential with its private key
        const { publicKey: issuerPublicKey, privateKey: issuerPrivateKey } = freshKeypair();
        const vc = buildVerifiableCredential(sampleInput());
        const vcJwt = signCredentialAsVcJwt(vc, issuerPrivateKey);

        // When — verifier checks with only the issuer's public key
        const result = verifyVcJwt(vcJwt, issuerPublicKey, { expectedIssuer: ISSUER_DID, now: NOW });

        // Then
        assert.equal(result.valid, true);
    });
});

describe('Lesson 2 — Enveloping: the credential is wrapped INSIDE the signed envelope', () => {
    test('decoding the JWS payload yields the credential under the `vc` claim', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const vc = buildVerifiableCredential(sampleInput());

        // When
        const vcJwt = signCredentialAsVcJwt(vc, privateKey);
        const { payload } = verifyJwsCompact(vcJwt, publicKey, 'ES256');

        // Then — payload.vc IS the credential. The signature, in the third
        // segment of the JWS, sits OUTSIDE this nesting.
        assert.deepEqual(payload.vc, vc);
    });
});

describe('Lesson 3 — `@context` is mandatory; VCDM-compliant verifiers may reject VCs without it', () => {
    test('every VC built by Section 1 carries the W3C VC v2 context', () => {
        // Given
        const vc = buildVerifiableCredential(sampleInput());

        // Then
        assert.equal(vc['@context'][0], VC_CTX_V2);
    });
});
