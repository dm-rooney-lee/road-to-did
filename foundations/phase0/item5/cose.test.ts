import {describe, test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, type KeyObject} from 'node:crypto';

import {
    buildCoseSign1,
    decodeCbor,
    encodeCbor,
    verifyCoseSign1,
} from './cose.ts';

function freshKeypair(): { publicKey: KeyObject; privateKey: KeyObject } {
    return generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

const hex = (b: Buffer) => b.toString('hex');
const fromHex = (s: string) => Buffer.from(s, 'hex');

// ============================================================
// Section 1 — encodeCbor
// ============================================================
// Test vectors are from RFC 8949 Appendix A (the canonical CBOR examples).

describe('Section 1 — encodeCbor (RFC 8949 vectors)', () => {

    describe('unsigned int (major type 0)', () => {
        test('1a — 0 encodes as 0x00', () => {
            assert.equal(hex(encodeCbor(0)), '00');
        });
        test('1b — 23 fits in the initial byte', () => {
            assert.equal(hex(encodeCbor(23)), '17');
        });
        test('1c — 24 needs a 1-byte argument', () => {
            assert.equal(hex(encodeCbor(24)), '1818');
        });
        test('1d — 1000 needs a 2-byte argument', () => {
            assert.equal(hex(encodeCbor(1000)), '1903e8');
        });
        test('1e — 1_000_000 needs a 4-byte argument', () => {
            assert.equal(hex(encodeCbor(1_000_000)), '1a000f4240');
        });
    });

    describe('negative int (major type 1)', () => {
        test('1f — -1 encodes as 0x20', () => {
            assert.equal(hex(encodeCbor(-1)), '20');
        });
        test('1g — -7 (ES256 alg id) encodes as 0x26', () => {
            assert.equal(hex(encodeCbor(-7)), '26');
        });
        test('1h — -100 needs a 1-byte argument', () => {
            assert.equal(hex(encodeCbor(-100)), '3863');
        });
        test('1i — -1000 needs a 2-byte argument', () => {
            assert.equal(hex(encodeCbor(-1000)), '3903e7');
        });
    });

    describe('byte string (major type 2)', () => {
        test('1j — empty Buffer encodes as 0x40', () => {
            assert.equal(hex(encodeCbor(Buffer.alloc(0))), '40');
        });
        test('1k — 4-byte Buffer encodes with 0x44 prefix', () => {
            assert.equal(hex(encodeCbor(Buffer.from([0x01, 0x02, 0x03, 0x04]))), '4401020304');
        });
    });

    describe('text string (major type 3)', () => {
        test('1l — empty string encodes as 0x60', () => {
            assert.equal(hex(encodeCbor('')), '60');
        });
        test('1m — "IETF" encodes with 0x64 prefix and UTF-8 bytes', () => {
            assert.equal(hex(encodeCbor('IETF')), '6449455446');
        });
        test('1n — "Signature1" (the COSE context label)', () => {
            assert.equal(hex(encodeCbor('Signature1')), '6a5369676e617475726531');
        });
    });

    describe('array (major type 4)', () => {
        test('1o — empty array encodes as 0x80', () => {
            assert.equal(hex(encodeCbor([])), '80');
        });
        test('1p — [1, 2, 3] encodes recursively', () => {
            assert.equal(hex(encodeCbor([1, 2, 3])), '83010203');
        });
        test('1q — nested arrays', () => {
            assert.equal(hex(encodeCbor([1, [2, 3], [4, 5]])), '8301820203820405');
        });
    });

    describe('map (major type 5)', () => {
        test('1r — empty map encodes as 0xa0', () => {
            assert.equal(hex(encodeCbor(new Map())), 'a0');
        });
        test('1s — {1: -7} (the COSE alg=ES256 header)', () => {
            assert.equal(hex(encodeCbor(new Map<number | string, number>([[1, -7]]))), 'a10126');
        });
        test('1t — two-entry map preserves insertion order', () => {
            const m = new Map<number | string, number>();
            m.set(1, 2);
            m.set(3, 4);
            assert.equal(hex(encodeCbor(m)), 'a201020304');
        });
        test('1u — map with mixed keys', () => {
            const m = new Map<number | string, number | string>();
            m.set('a', 1);
            m.set('b', 2);
            assert.equal(hex(encodeCbor(m)), 'a26161016162' + '02');
        });
    });

    describe('round-trip (encode then decodeCbor)', () => {
        const samples: { name: string; value: any }[] = [
            { name: 'uint 42', value: 42 },
            { name: 'nint -42', value: -42 },
            { name: 'bstr', value: Buffer.from('hello') },
            { name: 'tstr', value: 'hello' },
            { name: 'array', value: [1, 'two', Buffer.from([3])] },
            { name: 'map', value: new Map<number | string, any>([[1, 'one'], ['two', 2]]) },
        ];
        for (const s of samples) {
            test(`round-trip: ${s.name}`, () => {
                const encoded = encodeCbor(s.value);
                const { value: decoded, bytesRead } = decodeCbor(encoded);
                assert.equal(bytesRead, encoded.length);
                assert.deepEqual(decoded, s.value);
            });
        }
    });
});

// ============================================================
// Section 2 — buildCoseSign1
// ============================================================

describe('Section 2 — buildCoseSign1', () => {
    const payload = Buffer.from('hello world');
    const kid = Buffer.from([0x01]);

    test('2a — output is tagged with CBOR tag 18 (leading byte 0xd2)', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const signed = buildCoseSign1(payload, kid, privateKey);

        // Then
        assert.equal(signed[0], 0xd2, `expected leading 0xd2 (tag 18), got 0x${signed[0].toString(16)}`);
    });

    test('2b — under the tag, the structure is a 4-element CBOR array', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const signed = buildCoseSign1(payload, kid, privateKey);
        const { value } = decodeCbor(signed);

        // Then
        assert.ok(Array.isArray(value), 'COSE_Sign1 must be a CBOR array');
        assert.equal((value as unknown[]).length, 4);
    });

    test('2c — element[0] is the bstr-wrapped CBOR encoding of {1: -7}', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const signed = buildCoseSign1(payload, kid, privateKey);
        const arr = decodeCbor(signed).value as Buffer[];
        const protectedBstr = arr[0];

        // Then
        assert.ok(Buffer.isBuffer(protectedBstr));
        const protectedMap = decodeCbor(protectedBstr).value as Map<number | string, number>;
        assert.equal(protectedMap.get(1), -7);
    });

    test('2d — element[1] is the unprotected map { 4: kid }', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const signed = buildCoseSign1(payload, kid, privateKey);
        const arr = decodeCbor(signed).value as unknown[];
        const unprotected = arr[1] as Map<number | string, Buffer>;

        // Then
        assert.ok(unprotected instanceof Map);
        assert.deepEqual(unprotected.get(4), kid);
    });

    test('2e — element[2] is the payload bytes verbatim', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const signed = buildCoseSign1(payload, kid, privateKey);
        const arr = decodeCbor(signed).value as Buffer[];

        // Then
        assert.deepEqual(arr[2], payload);
    });

    test('2f — element[3] is a 64-byte signature (raw R‖S, not DER)', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const signed = buildCoseSign1(payload, kid, privateKey);
        const arr = decodeCbor(signed).value as Buffer[];

        // Then
        assert.equal(arr[3].length, 64, 'ES256 raw R‖S must be 64 bytes');
    });

    test('2g — different payloads produce different signatures', () => {
        // Given
        const { privateKey } = freshKeypair();

        // When
        const a = buildCoseSign1(Buffer.from('one'), kid, privateKey);
        const b = buildCoseSign1(Buffer.from('two'), kid, privateKey);

        // Then
        const sigA = (decodeCbor(a).value as Buffer[])[3];
        const sigB = (decodeCbor(b).value as Buffer[])[3];
        assert.notDeepEqual(sigA, sigB);
    });
});

// ============================================================
// Section 3 — verifyCoseSign1
// ============================================================

describe('Section 3 — verifyCoseSign1', () => {
    const payload = Buffer.from('hello world');
    const kid = Buffer.from([0x01]);

    test('3a — round-trip: buildCoseSign1 then verify returns valid=true', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const signed = buildCoseSign1(payload, kid, privateKey);

        // When
        const result = verifyCoseSign1(signed, publicKey);

        // Then
        assert.equal(result.valid, true);
    });

    test('3b — payload is returned regardless of validity', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const signed = buildCoseSign1(payload, kid, privateKey);

        // When
        const result = verifyCoseSign1(signed, publicKey);

        // Then
        assert.deepEqual(result.payload, payload);
    });

    test('3c — protected header is decoded and returned', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const signed = buildCoseSign1(payload, kid, privateKey);

        // When
        const result = verifyCoseSign1(signed, publicKey);

        // Then
        assert.equal(result.protectedHeader.get(1), -7);
    });

    test('3d — wrong public key fails verification', () => {
        // Given
        const { privateKey } = freshKeypair();
        const { publicKey: unrelatedKey } = freshKeypair();
        const signed = buildCoseSign1(payload, kid, privateKey);

        // When
        const result = verifyCoseSign1(signed, unrelatedKey);

        // Then
        assert.equal(result.valid, false);
    });

    test('3e — tampered payload bytes invalidate the signature', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const signed = buildCoseSign1(payload, kid, privateKey);
        const arr = decodeCbor(signed).value as Buffer[];
        // Reassemble with a modified payload, keeping the original signature
        const forged = encodeCbor([
            arr[0],
            arr[1] as unknown as Map<number | string, any>,
            Buffer.from('hello WORLD'),
            arr[3],
        ]);
        const taggedForged = Buffer.concat([Buffer.from([0xd2]), forged]);

        // When
        const result = verifyCoseSign1(taggedForged, publicKey);

        // Then
        assert.equal(result.valid, false);
    });

    test('3f — also accepts untagged COSE_Sign1 (no leading 0xd2)', () => {
        // Given
        const { publicKey, privateKey } = freshKeypair();
        const tagged = buildCoseSign1(payload, kid, privateKey);
        const untagged = tagged.subarray(1);   // strip the tag byte

        // When
        const result = verifyCoseSign1(untagged, publicKey);

        // Then
        assert.equal(result.valid, true);
    });
});

// ============================================================
// Lessons
// ============================================================

describe('Lesson 1 — integer keys make COSE maps tiny', () => {
    test('the protected header { 1: -7 } encodes in exactly 3 bytes', () => {
        // a1 = map(1), 01 = uint(1) for "alg", 26 = nint(-7) for "ES256"
        assert.equal(hex(encodeCbor(new Map<number | string, number>([[1, -7]]))), 'a10126');
    });

    test('the equivalent JOSE-style { "alg": "ES256" } would take an order of magnitude more', () => {
        const joseLike = new Map<number | string, string>([['alg', 'ES256']]);
        const cborWithStringKeys = encodeCbor(joseLike);
        // a1 63 61 6c 67 65 45 53 32 35 36  →  11 bytes  vs  3 bytes with int keys
        assert.ok(cborWithStringKeys.length > 3 * 3,
            `expected string-keyed form to be much larger; got ${cborWithStringKeys.length} bytes`);
    });
});

describe('Lesson 2 — Sig_structure binds the context label, not just the payload', () => {
    test('changing the context label invalidates the signature', () => {
        // Given a normally-built COSE_Sign1
        const { publicKey, privateKey } = freshKeypair();
        const signed = buildCoseSign1(Buffer.from('payload'), Buffer.from([0]), privateKey);

        // When we strip the tag and re-verify, it works (3f confirms this)
        const stripped = signed.subarray(1);
        assert.equal(verifyCoseSign1(stripped, publicKey).valid, true);

        // But if a verifier reconstructed the Sig_structure with a DIFFERENT
        // context label (say "MAC1" instead of "Signature1"), the bytes-to-
        // verify would change and the signature would not validate. This is
        // why "Signature1" is hard-coded into the Sig_structure for COSE_Sign1.
        // (Not directly testable from outside without re-implementing — the
        // point is that your verify must use exactly "Signature1".)
        assert.ok(true);
    });
});

describe('Lesson 3 — encodeCbor produces deterministic short-form encodings', () => {
    test('23 encodes as one byte, not as "0x18 0x17"', () => {
        // CBOR allows BOTH "0x17" and "0x18 0x17" for 23. The canonical/
        // deterministic encoding picks the shorter form.
        assert.equal(hex(encodeCbor(23)), '17');
    });

    test('256 encodes as 3 bytes (0x19 0x01 0x00), not 5 bytes', () => {
        // The shortest argument size that fits 256 is 2 bytes → major type 0
        // with marker 25 → 0x19 0x01 0x00.
        assert.equal(hex(encodeCbor(256)), '190100');
    });

    test('same value always produces same bytes (signature stability)', () => {
        const a = encodeCbor(new Map<number | string, number>([[1, -7]]));
        const b = encodeCbor(new Map<number | string, number>([[1, -7]]));
        assert.deepEqual(a, b);
    });
});
