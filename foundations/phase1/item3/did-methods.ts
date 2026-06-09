/**
 * Phase 1 — Item 03 · Major DID Methods compared
 *
 * READ FIRST  ./did-methods.notes.html  (the root-of-trust spectrum + each method's mapping)
 * IMPLEMENT   One function per section. Fill in each body.
 * VERIFY      npx tsx --test foundations/phase1/item3/did-methods.test.ts
 *
 * Item 02 deliberately stopped before DID *Resolution*: it handed you a DID
 * Document and you read it. But it left one sentence unexplained — "each method
 * defines its own rule for how a DID maps to a Document." This item makes that
 * concrete by implementing the mapping for three methods, chosen because they
 * sit at different points on the same axis:
 *
 *   WHERE DOES THE DOCUMENT COME FROM, AND WHOM DO YOU TRUST FOR IT?
 *
 *   did:jwk   the document is COMPUTED from the identifier. The identifier IS
 *             a public key (base64url-wrapped). No registry, no network. You
 *             trust the math. (Section 1)
 *   did:key   also computed from the identifier — the identifier is a public
 *             key in a self-describing binary envelope (multibase+multicodec).
 *             Same trust model as did:jwk, different envelope. (Section 2)
 *   did:web   the document is NOT in the identifier. The identifier names a
 *             domain; the document is fetched from an HTTPS URL under it. You
 *             trust that domain's DNS + TLS. (Section 3 derives the URL.)
 *
 * A fourth category — did:ion / did:ebsi — anchors the document on a ledger
 * and is covered conceptually in the notes only (no network or chain here).
 *
 * For did:key and did:jwk, "resolution" is just decoding, so it lives here.
 * The general resolution machinery — a resolver that dispatches on the method
 * name, fetches over the network for did:web, and reports resolution metadata
 * — is Item 04. Section 3 stops at the URL for exactly that reason.
 *
 * The Documents produced here are the same shape Item 02 built and read, so
 * they reuse its types and feed straight into its dereferenceVerificationMethod.
 */
import type {DidDocument, VerificationMethod} from '../item2/did.ts';

// A base58btc decoder and the multicodec prefix table are provided in
// ./multibase.cheatsheet.ts so Section 2 can focus on the did:key mapping
// rather than on re-deriving base58. Import from it if you want them.

function TODO(label: string): never {
    throw new Error(`TODO — ${label} not implemented`);
}

const DID_CTX_V1 = 'https://www.w3.org/ns/did/v1';
const JWS_2020_CTX = 'https://w3id.org/security/suites/jws-2020/v1';

// ============================================================
// Section 1 — Resolve a did:jwk (the did:jwk method)
//
//   Turn a did:jwk identifier into the DID Document it deterministically
//   denotes. did:jwk is the simplest possible "the key is the identifier"
//   method: there is nothing to fetch — the public key is literally encoded
//   in the identifier string.
//
//   Identifier form:
//     did:jwk:<base64url( utf8( JSON of a public JWK ) )>
//
//   Decoding:
//     1. The scheme must be exactly "did:jwk:". Reject otherwise.
//     2. base64url-decode the method-specific-id and JSON.parse it to recover
//        the public key JWK (an object such as
//        { "kty":"EC", "crv":"P-256", "x":"…", "y":"…" }).
//
//   Document to return:
//     @context           — [ DID_CTX_V1, JWS_2020_CTX ]
//     id                 — the did, verbatim.
//     verificationMethod — a single entry:
//                            id          = `${did}#0`
//                            type        = "JsonWebKey2020"
//                            controller  = did
//                            publicKeyJwk = the decoded JWK
//     verification relationships — each is an array holding the single
//        reference string `${did}#0`. WHICH relationships appear is gated by
//        the JWK's optional "use" member, because "use" declares what the key
//        is for:
//          • use === "sig"  → authentication, assertionMethod,
//                             capabilityInvocation, capabilityDelegation
//                             (a signing key; NO keyAgreement).
//          • use === "enc"  → keyAgreement only.
//          • use absent     → all five of the above.
//
//   Note on the verification method id: the did:jwk spec writes it as the bare
//   fragment "#0". We emit the absolute form `${did}#0` instead — the two are
//   equivalent once a relative DID URL is resolved against the document id, and
//   the absolute form drops straight into Item 02's dereferenceVerificationMethod.
// ============================================================

export function resolveDidJwk(did: string): DidDocument {
    return TODO('resolveDidJwk');
}

// ============================================================
// Section 2 — Resolve a did:key (the did:key method)
//
//   Turn a did:key identifier into the DID Document it deterministically
//   denotes. Same idea as did:jwk — the key is the identifier — but the key is
//   carried in a self-describing BINARY envelope instead of a JSON one.
//
//   Identifier form:
//     did:key:z<base58btc( <multicodec-prefix-bytes> || <raw-public-key-bytes> )>
//
//   The leading "z" is the multibase tag for base58btc. After base58btc-decoding
//   the part following "z", the first two bytes are the multicodec prefix (which
//   key type) and the remaining bytes are the raw public key. (See the cheatsheet
//   for base58btcDecode and the MULTICODEC_PREFIX table.)
//
//   Decoding:
//     1. The scheme must be "did:key:" and the method-specific-id must begin
//        with the multibase tag "z" (base58btc). Reject otherwise.
//     2. base58btc-decode the bytes after "z". Split off the first two bytes as
//        the multicodec prefix; the rest is the raw public key.
//     3. Map the prefix to a key type. This lab supports exactly two; reject
//        any other prefix as an unsupported curve:
//          ed25519-pub → { kty:"OKP", crv:"Ed25519" } — a SIGNING key
//          x25519-pub  → { kty:"OKP", crv:"X25519"  } — a KEY-AGREEMENT key
//        Build publicKeyJwk = { kty, crv, x: base64url(raw public key bytes) }.
//
//   Document to return:
//     @context           — [ DID_CTX_V1, JWS_2020_CTX ]
//     id                 — the did, verbatim.
//     verificationMethod — a single entry:
//                            id          = `${did}#${methodSpecificId}`
//                                          (the did:key convention: the fragment
//                                          equals the "z…" string itself)
//                            type        = "JsonWebKey2020"
//                            controller  = did
//                            publicKeyJwk = the JWK built above
//     verification relationships — gated by what the curve can do:
//          • an Ed25519 (signing) key → authentication, assertionMethod,
//                                       capabilityInvocation, capabilityDelegation.
//          • an X25519 (agreement) key → keyAgreement only.
//        Each present relationship is an array holding the single reference
//        string `${did}#${methodSpecificId}`.
//
//   Out of scope: a real did:key resolver, given an Ed25519 key, ALSO derives a
//   separate X25519 keyAgreement key by converting the Edwards point to its
//   Montgomery form. That curve conversion is not implemented here — this lab
//   stops at the key the identifier directly encodes.
// ============================================================

export function resolveDidKey(did: string): DidDocument {
    return TODO('resolveDidKey');
}

// ============================================================
// Section 3 — Derive a did:web document URL (the did:web method)
//
//   did:web breaks from the previous two: the document is NOT contained in the
//   identifier. The identifier names a place on the web, and the document is
//   whatever is hosted there right now. This function computes that place — the
//   HTTPS URL of the DID Document — but does NOT fetch it. (Fetching, and the
//   resolver that decides to fetch, are Item 04.)
//
//   Identifier form:
//     did:web:<authority>[ : <path-segment> ]*
//   Within the method-specific-id, ":" separates segments. A colon inside the
//   authority (a port) is percent-encoded as "%3A", so it is NOT a separator.
//
//   Deriving the URL (did:web method rules):
//     1. The scheme must be "did:web:" and the method-specific-id must be
//        non-empty. Reject otherwise.
//     2. Split the method-specific-id on ":" into segments.
//     3. Percent-decode each segment (so "example.com%3A3000" → "example.com:3000").
//     4. The first segment is the authority (host, optionally host:port). Any
//        remaining segments are path components.
//     5. If there are NO path components:
//          https://<authority>/.well-known/did.json
//        If there ARE path components:
//          https://<authority>/<segment>/<segment>/…/did.json
//
//   The contrast to carry away: with did:key / did:jwk the document is a pure
//   function of the identifier, so it cannot lie and cannot change. With did:web
//   the identifier only points; the document can be edited or replaced by
//   whoever controls the domain, and your trust in it reduces to your trust in
//   that domain's DNS and TLS.
// ============================================================

export function deriveDidWebUrl(did: string): string {
    return TODO('deriveDidWebUrl');
}

// ============================================================
// LESSONS (read after implementing and running the tests)
// ============================================================
//
// Lesson 1 — The method segment is a choice of root of trust
//   Every DID has the shape did:<method>:<id>, and Item 02 noted that the
//   method segment names "the rule for how a DID maps to a Document." Having
//   implemented three, you can see the rule is really a choice of WHO YOU TRUST
//   to vouch for the binding between identifier and key:
//
//     did:jwk / did:key  the binding is mathematical. The identifier is the
//                        key, so the document is a pure function of the string.
//                        Nobody vouches; nobody can lie. Trust = the decoding.
//     did:web            the binding is the web. The identifier names a domain;
//                        the document is hosted there. Trust = DNS + TLS + the
//                        operator of that server.
//     did:ion / did:ebsi the binding is a ledger. The document (or its history
//                        of signed updates) is anchored on a blockchain. Trust
//                        = the chain's consensus and the operations recorded on
//                        it. (Not implemented here — there is no chain to read.)
//
//   This is the "decentralized" knob from Item 02's Lesson 1, now concrete: the
//   same identifier shape ranges from "trust nothing but math" to "trust a
//   domain" to "trust a chain," and the method name is how you pick.
//
// Lesson 2 — Self-describing encodings, and why did:jwk ≠ did:key but ≈ did:key
//   did:jwk and did:key occupy the SAME point on the trust axis — the key is
//   the identifier in both. They differ only in the envelope:
//
//     did:jwk   base64url of a JSON JWK. Human-legible after one decode; the
//               key type is named in plain text ("kty","crv"). Verbose.
//     did:key   base58btc of (multicodec-prefix ‖ raw key). Compact binary; the
//               key type is a numeric multicodec tag, not a word.
//
//   did:key's envelope is built from the "multi-" family of self-describing
//   formats: multibase (a one-char prefix naming the base — "z" = base58btc)
//   wraps multicodec (a varint prefix naming the value's type). "Self-describing"
//   means the bytes carry their own type tag, so a reader never needs to be told
//   out-of-band how to interpret them — exactly what let Section 2 dispatch on
//   the first two bytes. You will meet this family again in multihash (how a
//   hash announces which algorithm produced it) and elsewhere in the IPFS/
//   content-addressing world that did:key borrows from.
//
// Lesson 3 — In the identifier vs hosted/anchored: the rotation trade-off
//   Carrying the document inside the identifier (did:jwk, did:key) buys
//   immutability and zero infrastructure — but the cost is that the key can
//   NEVER rotate: change the key and you have changed the DID, because the DID
//   was the key. There is no "same identity, new key."
//
//   Hosting (did:web) or anchoring (did:ion) the document buys exactly that:
//   the identifier is stable while the keys inside its document can be added,
//   retired, and replaced over time. The price is the trust dependency Lesson 1
//   named — a server or a chain you now have to rely on, and that can change the
//   document out from under a verifier.
//
//   This is why did:key is the right tool for an ephemeral key (a single
//   presentation, a short-lived session) and did:web / did:ion for a durable
//   issuer identity that must outlive any one key. When Item 01's verifier asked
//   for "the issuer's public key," the method behind the issuer's DID is what
//   decided whether that key could ever have changed — and how the verifier
//   would have found out.
//
//   Item 04 (DID Resolution) builds the layer above all of this: one resolve()
//   entry point that looks at the method segment, routes to the right rule
//   (decode for did:key/did:jwk, fetch the URL from Section 3 for did:web), and
//   returns the Document plus metadata about how the resolution went.
