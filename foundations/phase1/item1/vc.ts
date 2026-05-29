/**
 * Phase 1 — Item 01 · W3C Verifiable Credential Data Model 2.0 (as VC-JWT)
 *
 * READ FIRST  ./vc.notes.html  (trust triangle + VC anatomy + VC-JWT structure)
 * IMPLEMENT   One function per section. Fill in each body.
 * VERIFY      npx tsx --test foundations/phase1/item1/vc.test.ts
 *
 * Phase 0 built the primitives: ES256 signing (Item 02), JWS encoding (Item 02),
 * claim discipline (Item 04). Phase 1 starts layering W3C identity standards on
 * top. The first artifact is a *Verifiable Credential* — a structured JSON
 * object an issuer signs and hands to a holder.
 *
 * VCDM 2.0 separates two concerns:
 *   1. The credential STRUCTURE — what fields a VC has, what they mean.
 *      (Defined by the W3C VC Data Model 2.0 itself.)
 *   2. The credential SECURING — how the VC is signed/verifiable.
 *      (Defined by separate specs: "Securing VCs with JOSE and COSE" for
 *      VC-JWT; "Data Integrity" for embedded proofs.)
 *
 * This lab implements the VC-JWT path: the simpler securing mechanism, the one
 * that builds directly on what you already have from Phase 0. Data Integrity
 * proofs are covered in Lesson 2 but not implemented here.
 */

import {type KeyObject, randomUUID} from 'node:crypto';
import {encodeJwsCompact, verifyJwsCompact} from "../../phase0/item2/jwt.ts";

function TODO(label: string): never {
    throw new Error(`TODO — ${label} not implemented`);
}

// ============================================================
// Types
// ============================================================

export type CredentialInput = {
    issuer: string;                           // DID URL of the issuer
    subject: string;                          // DID URL of the credential subject
    type: string[];                           // MUST contain "VerifiableCredential" (caller responsibility)
    '@context': string[];                     // first element MUST be the v2 context (caller responsibility)
    claims: Record<string, unknown>;          // claims about the subject (other than id)
    id?: string;                              // credential id (URN); auto-generated if absent
    validFrom?: string;                       // ISO 8601 datetime
    validUntil?: string;                      // ISO 8601 datetime
};

export type VerifiableCredential = {
    '@context': string[];
    id?: string;
    type: string[];
    issuer: string;
    validFrom?: string;
    validUntil?: string;
    credentialSubject: { id: string } & Record<string, unknown>;
};

// ============================================================
// Section 1 — Assemble a Verifiable Credential (VCDM 2.0)
//
//   Build a well-formed VC JSON object from the input fields.
//
//   Output structure per W3C VC Data Model 2.0 §4 (Basic Concepts):
//     @context           — pass-through from input['@context']. The caller is
//                          responsible for including the VCDM 2.0 context
//                          "https://www.w3.org/ns/credentials/v2" as the first
//                          element. The function does not add or reorder; it
//                          trusts the caller. (Verification of @context[0]
//                          happens on the verifier side — see Section 3.)
//     id                 — optional in VCDM 2.0; if the caller didn't supply
//                          one, AUTO-GENERATE a URN UUID:
//                              `urn:uuid:${randomUUID()}`
//
//                          Why auto-generate instead of leaving it undefined
//                          (since the spec allows that)?
//                            - credentialStatus references need a target id
//                              for revocation lookups
//                            - wallet storage uses id as the key for the
//                              credential record
//                            - audit logs and analytics dedupe by id
//                            - VC-JWT's jti claim is sourced from id; many
//                              downstream systems expect it present
//                          In practice almost every production VC needs an id,
//                          and production VC libraries (Sphereon, walt.id,
//                          EUDI Wallet libs) all auto-generate by default for
//                          this reason. This is the one place the function
//                          deliberately breaks the "trust the caller, no magic"
//                          principle — the convenience is worth it because
//                          missing-id-by-accident is a very common bug class.
//     type               — pass-through from input.type. The caller is
//                          responsible for including "VerifiableCredential"
//                          in the array. The function does not validate or
//                          add; it trusts the caller.
//     issuer             — pass through from input
//     validFrom          — pass through ISO 8601 string (if provided)
//     validUntil         — pass through ISO 8601 string (if provided)
//     credentialSubject  — object { id: input.subject, ...input.claims }
//
//   Field naming note: VCDM 2.0 renamed several fields from 1.x. validFrom/
//   validUntil replaced issuanceDate/expirationDate. credentialSubject is
//   unchanged. issuer is unchanged.
//
//   This function does NOT sign anything — it just builds the JSON. Signing
//   is Section 2's job.
// ============================================================

export function buildVerifiableCredential(input: CredentialInput): VerifiableCredential {
    const { issuer, subject, type, '@context': context, claims, id, validFrom, validUntil } = input;
    const vcId = id !== undefined ? id : `urn:uuid:${randomUUID()}`;

    return {
        "@context": context,
        id: vcId,
        type: type,
        issuer: issuer,
        validFrom: validFrom,
        validUntil: validUntil,
        credentialSubject: {
            id: subject,
            ...claims,
        }
    };
}

// ============================================================
// Section 2 — Sign a VC as a VC-JWT
//
//   Produce a compact JWS (ES256) whose payload is the VC-JWT claim set.
//   VC-JWT is the "enveloping" securing mechanism: the signature wraps the
//   credential rather than being embedded inside it.
//
//   The JWT header is fixed: { alg: 'ES256', typ: 'JWT' }
//
//   The JWT payload maps fields from the credential to standard JWT claims,
//   then carries the whole credential under a `vc` claim:
//
//     iss  ← credential.issuer
//     sub  ← credential.credentialSubject.id
//     jti  ← credential.id           (only if present)
//     nbf  ← Math.floor(Date.parse(credential.validFrom)  / 1000)
//                                    (only if validFrom present)
//     exp  ← Math.floor(Date.parse(credential.validUntil) / 1000)
//                                    (only if validUntil present)
//     vc   ← the entire credential object (verbatim)
//
//   Why both the JWT-level claims (iss, sub, nbf, exp) AND the full credential
//   in `vc`? It's a deliberate compromise from VC-JWT 1.0: the JWT claims let
//   plain-JWT verifiers process expiry and issuer without understanding VCs;
//   the `vc` claim preserves the original credential JSON for VC-aware code.
//   VCDM 2.0's JOSE securing mechanism keeps this dual representation.
//
//   Date conversion note: validFrom/validUntil are ISO 8601 datetime strings
//   in the VC; nbf/exp in the JWT are Unix seconds. Use Date.parse() (which
//   returns milliseconds) divided by 1000 and floored.
//
//   Inputs:
//     credential — a VC as produced by Section 1
//     privateKey — EC P-256 private KeyObject (the issuer's signing key)
//
//   Returns: compact JWS string `header.payload.signature`.
// ============================================================

export function signCredentialAsVcJwt(
    credential: VerifiableCredential,
    privateKey: KeyObject,
): string {
    const { '@context': context, id, type, issuer, validFrom, validUntil, credentialSubject } = credential;
    const nbf = validFrom === undefined ? validFrom
        : Math.floor(Date.parse(validFrom) / 1000);
    const exp = validUntil === undefined ? validUntil
        : Math.floor(Date.parse(validUntil) / 1000);

    const header = { alg: 'ES256', typ: 'JWT' } as const;
    const payload = {
        iss: issuer,
        sub: credentialSubject.id,
        jti: id,
        nbf: nbf,
        exp: exp,
        vc: credential,
    };

    const jwsCompact = encodeJwsCompact(header, payload, privateKey);

    return jwsCompact.token;
}

// ============================================================
// Section 3 — Verify a VC-JWT
//
//   Decode an incoming VC-JWT, verify its signature, and run claim discipline
//   against the verifier's expectations.
//
//   Inputs:
//     vcJwt        — compact JWS produced by some issuer
//     publicKey    — EC P-256 public KeyObject the verifier trusts for this issuer
//     expectations — what THIS verifier requires from a valid VC-JWT:
//                      expectedIssuer — if provided, payload.iss must equal this
//                      now            — current time in Unix seconds, used to
//                                       evaluate payload.exp; supplied by the
//                                       caller so tests are deterministic
//
//   Return shape (every field populated on every call):
//     valid       — true only if signature verifies AND every claim check passes
//     credential  — the decoded `vc` claim from the payload (returned regardless
//                   of validity, so callers can inspect what was claimed).
//                   Whenever `vc` is not a usable credential object — absent
//                   (undefined), null, or a non-object primitive — an empty
//                   object is returned in its place. credential is always a
//                   Record, never null/undefined.
//     reason      — when valid is false, identifies the FIRST check that failed,
//                   one of: 'signature' | 'iss' | 'exp' | 'vc' | 'vc-iss'.
//                   Undefined when valid is true.
//
//   Check order (short-circuits on the first failure):
//     1. signature  — alg discipline + cryptographic verify (Item 02)
//     2. iss        — only if expectations.expectedIssuer is set;
//                     payload.iss must equal expectations.expectedIssuer
//     3. exp        — only if payload.exp is set; reject if exp <= now
//     4. vc         — structural validation of the embedded credential:
//                       (a) payload.vc must be a non-null object
//                       (b) vc['@context'] must be an array
//                       (c) vc['@context'][0] must equal the VCDM 2.0 context
//                           "https://www.w3.org/ns/credentials/v2"
//                           (VCDM 1.x credentials, or credentials with
//                            unknown contexts as their first element, are
//                            rejected here)
//                       (d) vc.type must be an array containing
//                           "VerifiableCredential"
//     5. vc-iss     — payload.iss MUST equal payload.vc.issuer.
//                     The JWT-level issuer claim and the embedded credential's
//                     issuer must agree. This defends against forged tokens
//                     where the JWT-level claim is honest but the inner
//                     credential lies about who issued it (or vice versa).
// ============================================================

export type VcJwtExpectations = {
    expectedIssuer?: string;
    now: number;
};

export type VcJwtVerifyResult = {
    valid: boolean;
    credential: Record<string, unknown>;
    reason?: 'signature' | 'iss' | 'exp' | 'vc' | 'vc-iss';
};

export function verifyVcJwt(
    vcJwt: string,
    publicKey: KeyObject,
    expectations: VcJwtExpectations,
): VcJwtVerifyResult {
    const { valid, payload } = verifyJwsCompact(vcJwt, publicKey, 'ES256');
    const isVcInvalid = payload.vc === undefined || payload.vc === null || typeof payload.vc !== 'object';
    if (!valid) {
        const vc = isVcInvalid ? {} : payload.vc as Record<string, unknown>;
        return {valid: false, credential: vc, reason: 'signature'};
    } else if (isVcInvalid) {
        return {valid: false, credential: {}, reason: 'vc'};
    }

    const { expectedIssuer, now } = expectations;
    const vc = payload.vc as Record<string, unknown>;
    const context = vc['@context'];
    const type = vc['type'];
    const defaultContext = 'https://www.w3.org/ns/credentials/v2';
    if (expectedIssuer !== undefined && expectedIssuer !== payload.iss) {
        return {valid: false, credential: vc, reason: 'iss'};
    } else if (payload.exp !== undefined && typeof payload.exp === 'number' && payload.exp <= now) {
        return {valid: false, credential: vc, reason: 'exp'};
    } else if (!Array.isArray(context) || context.length === 0 || context[0] !== defaultContext) {
        return {valid: false, credential: vc, reason: 'vc'};
    } else if (!Array.isArray(type) || type.length === 0 || !type.includes('VerifiableCredential')) {
        return {valid: false, credential: vc, reason: 'vc'};
    } else if (payload.iss !== vc.issuer) {
        return {valid: false, credential: vc, reason: 'vc-iss'};
    }

    return {valid: true, credential: vc};
}

// ============================================================
// LESSONS (read after implementing and running the tests)
// ============================================================
//
// Lesson 1 — The Issuer / Holder / Verifier trust triangle
//   Three roles, three different keys, three different responsibilities.
//   SSI (Self-Sovereign Identity)'s foundational diagram is a triangle with
//   these three at the corners:
//
//     Issuer    — the party that vouches for the claims. Signs the credential
//                 with its private key (e.g. a university signing a degree).
//                 Publishes its public key via DID Document or JWKS endpoint.
//
//     Holder    — the party that holds the credential after issuance. Doesn't
//                 need to sign the credential — they received it already
//                 signed. They DO sign Verifiable Presentations to prove
//                 control of the subject DID (key binding; Phase 2 material).
//
//     Verifier  — the party that consumes the credential later. Fetches the
//                 issuer's public key, verifies the signature, checks the
//                 claims, decides whether to trust.
//
//   The credential is signed once by the issuer and travels through the
//   holder to the verifier. The holder cannot modify it without invalidating
//   the signature. The verifier never talks to the issuer (in the simple
//   case) — they just need the issuer's public key.
//
//   This three-party split is what makes VCs "decentralized" relative to
//   OIDC's two-party RP↔OP flow. In OIDC, the OP is online during every
//   login. In VC, the issuer can be offline once the credential has been
//   issued; the verifier only needs the public key.
//
// Lesson 2 — Enveloping vs Embedded proofs
//   VCDM 2.0 supports two securing mechanisms; they're not interchangeable
//   but they prove the same thing:
//
//     Enveloping (VC-JWT, what this lab builds):
//       The credential JSON is wrapped INSIDE a signed envelope (the JWS).
//       The wire format is `header.payload.signature` — the credential
//       lives in the payload as the `vc` claim. The signature is OUTSIDE
//       the credential. To verify, you parse the JWS, extract the credential,
//       and check the signature over the encoded payload bytes.
//
//     Embedded (Data Integrity):
//       The credential JSON has a `proof` field added INSIDE it. The
//       signature is computed over a canonicalized form of the credential
//       (minus the proof field itself). To verify, you canonicalize the
//       credential the same way and check the signature.
//
//   Trade-offs:
//     VC-JWT       — simpler, builds on JOSE infrastructure, no JSON-LD
//                    processing required. Widely supported.
//     Data Integrity — keeps the credential as plain JSON-LD readable
//                      without unwrapping. Supports multiple proofs natively
//                      (multi-issuer, key rotation transitions). Requires
//                      JSON-LD canonicalization (URDNA2015), which is a
//                      whole other dependency.
//
//   In practice: SD-JWT VC (Phase 2) and OpenID4VC (Phase 3) use the
//   enveloping path. The legacy linked-data signature community (Sphereon,
//   walt.id older versions) uses Data Integrity. Both are valid VCDM 2.0
//   credentials.
//
// Lesson 3 — `@context` and JSON-LD (just enough to know what's happening)
//   Every VC has a `@context` array, with `"https://www.w3.org/ns/credentials/v2"`
//   as the first element. What does it do?
//
//   `@context` is a JSON-LD construct. JSON-LD ("JSON for Linked Data") is
//   a way of giving JSON documents global, unambiguous meaning by mapping
//   short field names to full IRIs. The W3C VC v2 context defines what
//   `issuer`, `credentialSubject`, `validFrom`, etc. mean in terms of RDF
//   triples. A JSON-LD processor can expand a VC into its full IRI form
//   and then reason about it semantically (e.g. for federated queries
//   across credentials from different issuers using different vocabularies).
//
//   For VC-JWT processing, you almost never need to do this expansion.
//   The verifier reads the credential as plain JSON, checks the standard
//   fields (issuer, credentialSubject, etc.), and trusts that the context
//   field's presence indicates VCDM compliance. The JSON-LD machinery
//   matters only when:
//     • a verifier is performing Data Integrity verification (which
//       canonicalizes the credential as RDF before signing/verifying),
//     • a system is doing semantic-web-style reasoning over credentials,
//     • a credential uses extension types (custom claim vocabularies)
//       that need to be resolved to full IRIs.
//
//   Practical takeaway: include `@context` because the spec mandates it
//   and verifiers may reject credentials without it. Don't worry about
//   what JSON-LD does at the byte level until Phase 2 or 4 when you meet
//   Data Integrity proofs or selective disclosure.
