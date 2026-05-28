/**
 * 05 — CBOR / COSE  ▸  cheatsheet (reference implementation of encodeCbor)
 *
 * This file is NOT imported by the lab. It exists as a reference for the
 * Section 1 encoder, with every line annotated to explain what it does and
 * why. Read it AFTER attempting Section 1 yourself, or use it as a guide
 * if you decide to skip the encoder grind.
 *
 * The CBOR rule in one sentence:
 *   Every value emits an *initial byte* that packs (major type, argument or
 *   size marker), followed by 0/1/2/4/8 argument bytes (big-endian), followed
 *   by payload bytes for length-prefixed types (bstr/tstr/array/map).
 *
 * The trick to implementing this cleanly: extract the "initial byte + arg
 * bytes" pattern into a single helper. Then each major type's encoder
 * shrinks to three lines: compute the size, call the helper, append payload.
 */

import type {CborValue} from './cose.ts';

// ============================================================
// Building block — cborHead
//
//   Produces the prefix bytes shared by EVERY CBOR value:
//     • one initial byte that packs major type (top 3 bits) and either the
//       value-or-length itself (bottom 5 bits, if it fits in 0..23) or a
//       marker indicating how many bytes of argument follow
//     • 0, 1, 2, 4, or 8 additional bytes (big-endian) holding the argument
//       when it didn't fit in the bottom 5 bits
//
//   "Argument" means different things for different major types:
//     uint   → the value itself
//     nint   → -(value+1)  (so -1 → 0, -7 → 6, etc.)
//     bstr   → the length in bytes of the payload
//     tstr   → the length in UTF-8 bytes
//     array  → the number of items
//     map    → the number of (key, value) pairs
//
//   cborHead doesn't know which it is — it just takes (majorType, arg) and
//   packs them. The caller (e.g. encodeCbor) is responsible for deciding
//   what "arg" means for the value being encoded.
// ============================================================

function cborHead(majorType: number, arg: number): Buffer {
    // Case A: arg fits in the bottom 5 bits of the initial byte (0..23).
    // Layout:  [ mmm aaaaa ]   where mmm = majorType, aaaaa = arg
    // Example: cborHead(0, 23)
    //   (0 << 5) | 23   →   0b00010111   →   0x17
    if (arg < 24) {
        return Buffer.from([(majorType << 5) | arg]);
    }

    // Case B: 1-byte argument follows. Marker 24 in bottom 5 bits.
    // Layout:  [ mmm 11000 ] [ arg ]
    // Example: cborHead(0, 24)
    //   initial byte: (0 << 5) | 24 = 0x18
    //   arg byte:     24            = 0x18
    //   result: 0x18 0x18
    if (arg < 256) {
        return Buffer.from([(majorType << 5) | 24, arg]);
    }

    // Case C: 2-byte big-endian argument follows. Marker 25.
    // Example: cborHead(0, 1000)
    //   initial byte: (0 << 5) | 25 = 0x19
    //   arg bytes:    0x03 0xe8     (1000 = 0x03e8)
    //   result: 0x19 0x03 0xe8
    if (arg < 65536) {
        const buf = Buffer.alloc(3);
        buf[0] = (majorType << 5) | 25;
        buf.writeUInt16BE(arg, 1);
        return buf;
    }

    // Case D: 4-byte big-endian argument follows. Marker 26.
    // Example: cborHead(0, 1_000_000)
    //   initial byte: (0 << 5) | 26 = 0x1a
    //   arg bytes:    0x00 0x0f 0x42 0x40  (1_000_000)
    //   result: 0x1a 0x00 0x0f 0x42 0x40
    if (arg < 2 ** 32) {
        const buf = Buffer.alloc(5);
        buf[0] = (majorType << 5) | 26;
        buf.writeUInt32BE(arg, 1);
        return buf;
    }

    // Case E: 8-byte big-endian argument follows. Marker 27.
    // For very large lengths/values. BigInt because JS numbers lose precision
    // beyond 2^53, but the wire wants the full 64 bits big-endian.
    const buf = Buffer.alloc(9);
    buf[0] = (majorType << 5) | 27;
    buf.writeBigUInt64BE(BigInt(arg), 1);
    return buf;
}

// ============================================================
// encodeCbor — dispatch on JS type, then delegate to cborHead + payload
//
//   The function is essentially a switch on the runtime type of `value`.
//   For each branch:
//     1. Compute the argument that cborHead needs (the value for ints,
//        the length for length-prefixed types).
//     2. Call cborHead to get the prefix bytes.
//     3. For length-prefixed types, concat the payload bytes after.
//     4. For recursive types (array, map), recursively encode each child
//        and concat.
//
//   That's the whole structure.
// ============================================================

export function encodeCbor(value: CborValue): Buffer {

    // ── number ────────────────────────────────────────────────────────
    // Split on sign. Major type 0 for ≥ 0, major type 1 for < 0.
    // For nints, the argument is the offset: arg = -1 - value, so
    //   -1 → arg=0, -7 → arg=6, -100 → arg=99.
    if (typeof value === 'number') {
        if (value >= 0) {
            return cborHead(0, value);
        } else {
            return cborHead(1, -1 - value);
        }
    }

    // ── byte string (Buffer) ──────────────────────────────────────────
    // Buffer.isBuffer is the strict check (not a Uint8Array — those are
    // different). Argument = length. Payload = the bytes themselves.
    if (Buffer.isBuffer(value)) {
        return Buffer.concat([cborHead(2, value.length), value]);
    }

    // ── text string ───────────────────────────────────────────────────
    // CBOR text strings are length-prefixed UTF-8 byte sequences. The
    // length is in BYTES of the UTF-8 encoding, not in characters. So
    // "hello" is 5 bytes; "héllo" is 6 bytes (é = two UTF-8 bytes).
    if (typeof value === 'string') {
        const utf8 = Buffer.from(value, 'utf8');
        return Buffer.concat([cborHead(3, utf8.length), utf8]);
    }

    // ── array ─────────────────────────────────────────────────────────
    // Argument = number of items. Each item recursively encoded.
    // Order matters: array elements are written in order.
    if (Array.isArray(value)) {
        const parts: Buffer[] = [cborHead(4, value.length)];
        for (const item of value) {
            parts.push(encodeCbor(item));
        }
        return Buffer.concat(parts);
    }

    // ── map (JS Map) ──────────────────────────────────────────────────
    // Argument = number of (key, value) pairs. Each pair is two recursive
    // encodes: key first, then value. JS Map preserves insertion order,
    // which determines the wire order here. Canonical/deterministic CBOR
    // (per RFC 8949 §4.2) would sort keys; this lab doesn't enforce that.
    if (value instanceof Map) {
        const parts: Buffer[] = [cborHead(5, value.size)];
        for (const [k, v] of value) {
            parts.push(encodeCbor(k));
            parts.push(encodeCbor(v));
        }
        return Buffer.concat(parts);
    }

    // Defensive: shouldn't reach here for any value typed as CborValue.
    throw new Error(`encodeCbor: unsupported value type ${typeof value}`);
}

// ============================================================
// Worked examples — trace a few values through the code by hand
// ============================================================
//
// encodeCbor(0)
//   ▸ typeof 0 === 'number' && 0 >= 0
//   ▸ cborHead(0, 0)
//   ▸ 0 < 24 → return Buffer.from([(0 << 5) | 0]) = Buffer.from([0x00])
//   Result: 0x00
//
// encodeCbor(-7)
//   ▸ typeof -7 === 'number' && -7 < 0
//   ▸ cborHead(1, -1 - (-7)) = cborHead(1, 6)
//   ▸ 6 < 24 → return Buffer.from([(1 << 5) | 6])
//                            = Buffer.from([0x20 | 0x06])
//                            = Buffer.from([0x26])
//   Result: 0x26
//
// encodeCbor(1000)
//   ▸ typeof 1000 === 'number' && 1000 >= 0
//   ▸ cborHead(0, 1000)
//   ▸ 1000 >= 256 && 1000 < 65536 → Case C (2-byte arg)
//   ▸ initial byte: (0 << 5) | 25 = 0x19
//   ▸ writeUInt16BE(1000, 1) → 0x03 0xe8
//   Result: 0x19 0x03 0xe8
//
// encodeCbor(Buffer.from([1, 2, 3, 4]))
//   ▸ Buffer.isBuffer ✓, length = 4
//   ▸ cborHead(2, 4): 4 < 24 → Buffer.from([(2 << 5) | 4]) = Buffer.from([0x44])
//   ▸ Buffer.concat([ [0x44], [0x01, 0x02, 0x03, 0x04] ])
//   Result: 0x44 0x01 0x02 0x03 0x04
//
// encodeCbor("IETF")
//   ▸ typeof "IETF" === 'string'
//   ▸ utf8 = Buffer.from("IETF", 'utf8') = [0x49, 0x45, 0x54, 0x46]  (4 bytes)
//   ▸ cborHead(3, 4) = Buffer.from([(3 << 5) | 4]) = Buffer.from([0x64])
//   ▸ concat → 0x64 0x49 0x45 0x54 0x46
//   Result: 0x64 0x49 0x45 0x54 0x46
//
// encodeCbor(new Map([[1, -7]]))     // the COSE protected header { alg: ES256 }
//   ▸ value instanceof Map, size = 1
//   ▸ cborHead(5, 1) = Buffer.from([(5 << 5) | 1]) = Buffer.from([0xa1])
//   ▸ for [k=1, v=-7]:
//       encodeCbor(1)  = cborHead(0, 1)  = Buffer.from([0x01])
//       encodeCbor(-7) = cborHead(1, 6)  = Buffer.from([0x26])
//   ▸ concat → 0xa1 0x01 0x26
//   Result: 0xa1 0x01 0x26     ← exactly 3 bytes for the COSE alg header
//
// encodeCbor([1, [2, 3], [4, 5]])    // nested array
//   ▸ Array.isArray ✓, length = 3
//   ▸ cborHead(4, 3) = Buffer.from([0x83])
//   ▸ encodeCbor(1)         → [0x01]
//   ▸ encodeCbor([2, 3])    → 0x82 0x02 0x03    (recursion)
//   ▸ encodeCbor([4, 5])    → 0x82 0x04 0x05
//   ▸ concat → 0x83 0x01 0x82 0x02 0x03 0x82 0x04 0x05
//   Result: 0x83 0x01 0x82 0x02 0x03 0x82 0x04 0x05

// ============================================================
// Why this implementation is "canonical/deterministic" for the subset
// ============================================================
//
// RFC 8949 §4.2 defines deterministic encoding rules. This implementation
// satisfies the relevant ones for the supported subset:
//
//   ✓ Integers use the shortest possible encoding.
//       cborHead picks the smallest size class that fits. There's no path
//       in the code that uses a longer encoding when a shorter one would
//       fit.
//
//   ✓ Length-prefixed types use the shortest length encoding.
//       Same logic — cborHead is called with the actual length, and it
//       picks the smallest size class.
//
//   ✓ No indefinite-length encodings.
//       This implementation doesn't emit those at all.
//
//   ✗ Map keys are NOT sorted.
//       This implementation writes keys in insertion order. Real canonical
//       CBOR sorts keys by their byte-encoded representation. The lab
//       doesn't enforce this because none of the tests need it; mDL/mdoc
//       does, and you'd add a sort before the for-loop over [k, v] entries.
//
// Adding key sorting (if you ever extend this) is a one-line change:
//   const entries = [...value].sort(([a], [b]) => byteCompare(encodeCbor(a),
//                                                            encodeCbor(b)));
// where byteCompare is lexicographic byte comparison.
