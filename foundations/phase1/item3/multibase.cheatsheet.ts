/**
 * Phase 1 / Item 03 — DID Methods  ▸  cheatsheet (multibase + multicodec)
 *
 * This file is NOT imported by the lab itself — Section 2 (resolveDidKey)
 * imports the two helpers it exports. It exists so you can spend your effort
 * on what is *new* in did:key — the multibase / multicodec mapping rules —
 * rather than on re-deriving base58btc, which is pure byte plumbing (the same
 * stance Item 05 took with the CBOR encoder).
 *
 * Two self-describing layers stack inside the part of a did:key after
 * "did:key:":
 *
 *   multibase   — a one-character prefix that says WHICH base the rest is
 *                 written in. did:key always uses base58btc, whose prefix is
 *                 the single letter 'z'. So every did:key identifier looks
 *                 like  did:key:z....  — strip the 'z', base58btc-decode the
 *                 rest, and you hold raw bytes.
 *
 *   multicodec  — once you have raw bytes, the FIRST few bytes are a varint
 *                 code that says WHAT KIND of key the remaining bytes are
 *                 (Ed25519 public key? X25519? secp256k1?). Strip the code,
 *                 and the tail is the raw public key.
 *
 * Both layers are "self-describing": the value carries its own type tag, so a
 * reader never has to be told out-of-band how to interpret it. That is the
 * recurring idea behind the `multi*` family (multibase, multicodec, multihash,
 * multiaddr).
 *
 * Read base58btcDecode if you're curious how the base change works; you only
 * NEED to call it. MULTICODEC_PREFIX is the lookup table Section 2 dispatches
 * on.
 */

// ============================================================
// base58btc — the Bitcoin alphabet, no 0/O/I/l to avoid visual ambiguity
// ============================================================

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

// reverse map: character → its value 0..57
const B58_MAP: Record<string, number> = {};
for (let i = 0; i < B58_ALPHABET.length; i++) {
    B58_MAP[B58_ALPHABET[i]] = i;
}

/**
 * Decode a base58btc string into the bytes it represents.
 *
 * The algorithm is plain positional base conversion (base 58 → base 256)
 * done with a big-integer, plus one special rule for leading zeros.
 *
 *   1. Treat the string as a base-58 number, most-significant digit first.
 *      Accumulate it into a BigInt:  acc = acc * 58 + digitValue.
 *   2. Emit that BigInt as big-endian base-256 bytes.
 *   3. Leading-zero rule: a base-256 zero byte (0x00) base58-encodes to the
 *      digit '1' (value 0), and a big-integer would otherwise swallow those
 *      leading zeros. So every leading '1' in the input maps to one leading
 *      0x00 byte in the output, prepended after the conversion.
 */
export function base58btcDecode(input: string): Buffer {
    let acc = 0n;
    for (const ch of input) {
        const value = B58_MAP[ch];
        if (value === undefined) {
            throw new Error(`base58btcDecode: illegal character ${JSON.stringify(ch)}`);
        }
        acc = acc * 58n + BigInt(value);
    }

    // BigInt → big-endian bytes
    const bytes: number[] = [];
    while (acc > 0n) {
        bytes.unshift(Number(acc & 0xffn));
        acc >>= 8n;
    }

    // restore leading zero bytes (one per leading '1')
    let leadingOnes = 0;
    for (const ch of input) {
        if (ch === '1') leadingOnes++;
        else break;
    }

    return Buffer.from([...new Array(leadingOnes).fill(0), ...bytes]);
}

/**
 * Encode bytes as a base58btc string. The inverse of base58btcDecode.
 * Included for symmetry / for building your own test vectors; resolveDidKey
 * only needs the decoder.
 */
export function base58btcEncode(bytes: Buffer): string {
    let acc = 0n;
    for (const b of bytes) {
        acc = acc * 256n + BigInt(b);
    }

    let out = '';
    while (acc > 0n) {
        const rem = Number(acc % 58n);
        out = B58_ALPHABET[rem] + out;
        acc /= 58n;
    }

    // leading 0x00 bytes → leading '1's
    for (const b of bytes) {
        if (b === 0) out = '1' + out;
        else break;
    }

    return out;
}

// ============================================================
// multicodec — the public-key codes did:key uses
//
//   Each entry is the unsigned-varint encoding of the multicodec number, as
//   raw bytes. For the public-key codes did:key uses, the varint is two bytes.
//
//   Examples (how the two bytes arise, for the curious):
//     ed25519-pub  = 0xed   → varint 0xed 0x01
//     x25519-pub   = 0xec   → varint 0xec 0x01
//     secp256k1-pub= 0xe7   → varint 0xe7 0x01
//     p256-pub     = 0x1200 → varint 0x80 0x24
//
//   You do NOT need to decode varints in this lab: every code below is exactly
//   two bytes, so Section 2 can treat "the first two bytes" as the codec and
//   "the rest" as the raw key. (A fully general did:key resolver would decode
//   the varint to learn the prefix length; that generality is out of scope.)
// ============================================================

export const MULTICODEC_PREFIX = {
    ed25519Pub:   Buffer.from([0xed, 0x01]),
    x25519Pub:    Buffer.from([0xec, 0x01]),
    secp256k1Pub: Buffer.from([0xe7, 0x01]),
    p256Pub:      Buffer.from([0x80, 0x24]),
} as const;
