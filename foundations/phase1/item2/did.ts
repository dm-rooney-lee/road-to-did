/**
 * Phase 1 — Item 02 · W3C Decentralized Identifiers (DID) Core 1.0
 *
 * READ FIRST  ./did.notes.html  (DID syntax + DID Document anatomy + dereferencing)
 * IMPLEMENT   One function per section. Fill in each body.
 * VERIFY      npx tsx --test foundations/phase1/item2/did.test.ts
 *
 * Item 01 built a Verifiable Credential and a verifier that needed "the issuer's
 * public key the verifier trusts for this issuer." It took that key as a given
 * KeyObject parameter. This item answers the question that parameter glossed
 * over: given only an identifier, how do you find the key?
 *
 * A DID (Decentralized Identifier) is that identifier. It is a string that:
 *   1. is globally unique without a central registrar, and
 *   2. resolves to a DID Document — a JSON object listing the public keys
 *      (and services) that the identifier's controller has published.
 *
 * DID Core 1.0 defines two things, and this lab implements the parts of both
 * that don't require network or ledger access:
 *   1. The DID *syntax* — the grammar of the identifier string itself.
 *      (Section 1)
 *   2. The DID *Document* — the data model the identifier points at, and how
 *      you pick a single key out of it. (Sections 2 and 3)
 *
 * What this lab does NOT cover: DID *Resolution* — the act of going from a DID
 * string to its Document over some method-specific mechanism (HTTP for did:web,
 * a ledger for did:ion, pure decoding for did:key). That is Item 04. Here the
 * Document is handed to you; you parse identifiers and read Documents.
 */
import * as vm from "node:vm";

function TODO(label: string): never {
    throw new Error(`TODO — ${label} not implemented`);
}

// ============================================================
// Types
// ============================================================

export type DidUrlParts = {
    did: string;                 // the bare DID: "did:" + method + ":" + methodSpecificId, with NO path/query/fragment
    method: string;              // method name, e.g. "example", "web", "key"
    methodSpecificId: string;    // everything after "did:<method>:" up to any path/query/fragment
    path?: string;               // path-abempty INCLUDING its leading "/", e.g. "/path/to/res"; absent if none
    query?: string;              // query WITHOUT the leading "?", e.g. "service=files"; absent if none
    fragment?: string;           // fragment WITHOUT the leading "#", e.g. "key-1"; absent if none
};

export type VerificationMethod = {
    id: string;                            // a DID URL, conventionally the DID + "#" + a key id, e.g. "did:example:123#key-1"
    type: string;                          // e.g. "JsonWebKey2020"
    controller: string;                    // the DID that controls this key
    publicKeyJwk?: Record<string, unknown>;
    publicKeyMultibase?: string;
};

// A verification relationship entry is EITHER an embedded VerificationMethod
// object OR a string reference to a VerificationMethod defined elsewhere in
// the same document.
export type VerificationRelationship = (string | VerificationMethod)[];

export type DidDocument = {
    '@context': string | string[];
    id: string;                            // the DID this document describes
    verificationMethod?: VerificationMethod[];
    authentication?: VerificationRelationship;
    assertionMethod?: VerificationRelationship;
    keyAgreement?: VerificationRelationship;
    capabilityInvocation?: VerificationRelationship;
    capabilityDelegation?: VerificationRelationship;
};

const DID_AND_URL_REGEX = /^(?<did>[^/?#]+)(?<url>[/?#].*)?$/;

// ============================================================
// Section 1 — Parse a DID URL (DID Core 1.0 §3.1, §3.2)
//
//   Split a DID or DID URL string into its structured components, rejecting
//   strings that do not conform to the grammar.
//
//   The DID grammar (DID Core §3.1, ABNF):
//     did                = "did:" method-name ":" method-specific-id
//     method-name        = 1*( %x61-7A / DIGIT )         ; lowercase a-z or 0-9
//     method-specific-id = *( *idchar ":" ) 1*idchar
//     idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
//     pct-encoded        = "%" HEXDIG HEXDIG
//
//   A DID URL (DID Core §3.2) layers the generic URI components on top:
//     did-url = did path-abempty [ "?" query ] [ "#" fragment ]
//
//   So a DID URL is a bare DID, optionally followed — in this order — by a
//   path (each segment introduced by "/"), a query (introduced by "?"), and
//   a fragment (introduced by "#").
//
//   Components to return (DidUrlParts):
//     did               — the bare DID with path/query/fragment stripped off.
//                         Always present in a valid input.
//     method            — the method-name.
//     methodSpecificId  — the method-specific-id (note: it may itself contain
//                         ":" separators, e.g. did:web:example.com:user:alice).
//     path              — present only if the input had a path; includes the
//                         leading "/".
//     query             — present only if the input had a query; excludes "?".
//     fragment          — present only if the input had a fragment; excludes "#".
//
//   Boundary rules among the optional parts:
//     - The fragment ("#") runs to the end of the string.
//     - The query ("?") runs up to the fragment (or end).
//     - The path ("/") runs up to the query or fragment (or end).
//
//   Validity: throw an Error if the input is not a syntactically valid DID URL.
//   In particular reject: a missing "did:" scheme; an empty or non-lowercase
//   method-name; an empty method-specific-id; method-specific-id characters
//   outside idchar.
//
//   Why parsing matters here: a verification method id like
//   "did:example:123#key-1" is a DID URL. To find that key in a document
//   (Section 3) you first separate the bare DID (which document?) from the
//   fragment (which key inside it?).
// ============================================================

export function parseDidUrl(didUrl: string): DidUrlParts {
    const didAndUrlMatch = didUrl.match(DID_AND_URL_REGEX);
    if (!didAndUrlMatch?.groups) {
        throw new Error(`Invalid didUrl: ${didUrl}`);
    }

    const {did, url} = didAndUrlMatch.groups;

    // parse did
    const [scheme, method, ...rest] = did.split(':');
    const methodId = rest.join(':');
    if (!scheme || scheme !== 'did') {
        throw new Error(`Invalid scheme: ${scheme}`);
    }

    const methodPattern = /^[a-z0-9]+$/;
    if (!method || !methodPattern.test(method)) {
        throw new Error(`Invalid method: ${method}`);
    }

    const methodIdPattern = /^([A-Za-z0-9:._-]|%[0-9A-Fa-f]{2})+$/;
    if (!methodId || !methodIdPattern.test(methodId)) {
        throw new Error(`Invalid methodId: ${methodId}`);
    }

    // parse url
    if (!url) {
        return {did: did, method: method, methodSpecificId: methodId};
    }

    const pathIndex = url.indexOf('/');
    const queryIndex = url.indexOf('?');
    const fragmentIndex = url.indexOf('#');

    const maybeHasPath = pathIndex !== -1;
    const maybeHasQuery = queryIndex !== -1;
    const maybeHasFragment = fragmentIndex !== -1;

    const delimitersIndices = [queryIndex, fragmentIndex].filter(i => i !== -1);
    const firstQueryOrFragmentIndex = delimitersIndices.length > 0
        ? Math.min(...delimitersIndices)
        : -1;

    let path: string | undefined = undefined;
    if (maybeHasPath) {
        if (firstQueryOrFragmentIndex === -1) {
            path = url.substring(pathIndex);
        } else if (firstQueryOrFragmentIndex > pathIndex) {
            path = url.substring(pathIndex, firstQueryOrFragmentIndex);
        }
    }

    let query: string | undefined = undefined;
    if (maybeHasQuery) {
        if (!maybeHasFragment) {
            query = url.substring(queryIndex + 1);
        } else if (queryIndex < fragmentIndex) {
            query = url.substring(queryIndex + 1, fragmentIndex);
        }
    }

    const fragment = !maybeHasFragment ? undefined : url.substring(fragmentIndex + 1);

    return {
        did: did,
        method: method,
        methodSpecificId: methodId,
        ...path !== undefined ? {path: path} : {},
        ...query !== undefined ? {query: query} : {},
        ...fragment !== undefined ? {fragment: fragment} : {},
    };
}

// ============================================================
// Section 2 — Build a DID Document (DID Core 1.0 §5, §6)
//
//   Assemble a well-formed DID Document JSON object describing one DID and the
//   keys it publishes.
//
//   Output structure:
//     @context           — pass through from input. The caller is responsible
//                          for including the DID v1 context
//                          "https://www.w3.org/ns/did/v1" as the first element;
//                          the function trusts the caller (same "no magic"
//                          stance as Item 01's @context handling).
//     id                 — the DID, pass through from input.did.
//     verificationMethod — pass through the input's verification methods array
//                          (each entry already a full VerificationMethod). Omit
//                          the property entirely if the input has none.
//     authentication,    — the two verification RELATIONSHIPS the input accepts.
//     assertionMethod      For each one the caller supplies, set it to an array
//                          of REFERENCE STRINGS (the VerificationMethod ids), not
//                          embedded copies — a document SHOULD reference a key
//                          defined once under verificationMethod rather than
//                          duplicate it. Omit either relationship the caller did
//                          not supply.
//
//   The caller passes, per relationship, the list of verification-method ids
//   that should be usable for that purpose. Every id listed for a relationship
//   MUST correspond to an id present in input.verificationMethods; reject
//   (throw) if a relationship references an id that is not defined.
//
//   This function does not generate keys or ids — it arranges already-formed
//   verification methods into a document and wires up the relationships.
// ============================================================

export type DidDocumentInput = {
    '@context': string[];
    did: string;
    verificationMethods: VerificationMethod[];
    authentication?: string[];          // VerificationMethod ids usable for authentication
    assertionMethod?: string[];         // VerificationMethod ids usable for assertion (VC issuance)
};

export function buildDidDocument(input: DidDocumentInput): DidDocument {
    const {'@context': context, did, verificationMethods, authentication, assertionMethod} = input;
    const ids = verificationMethods.map(method => method.id);
    if (authentication) {
        const isAuthenticationValid = authentication.every(auth => ids.includes(auth));
        if (!isAuthenticationValid) {
            throw new Error(`Authentication IDs not match verificationIds:
             authenticationIds=${authentication}, verificationIds=${ids}`);
        }
    }

    if (assertionMethod) {
        const isAssertionValid = assertionMethod.every(assertion => ids.includes(assertion));
        if (!isAssertionValid) {
            throw new Error(`Assertion IDs not match verificationIds:
             assertionIds=${assertionMethod}, verificationIds=${ids}`);
        }
    }

    return {
        '@context': context,
        id: did,
        verificationMethod: verificationMethods,
        ...authentication !== undefined ? {authentication: authentication} : {},
        ...assertionMethod !== undefined ? {assertionMethod: assertionMethod} : {},
    };
}

// ============================================================
// Section 3 — Dereference a verification method (DID Core 1.0 §3.2, §5.3)
//
//   Given a DID Document and a DID-URL reference that ends in a fragment,
//   return the VerificationMethod that fragment identifies — or null if no
//   such method exists in this document.
//
//   Inputs:
//     didDocument — a DID Document (as produced by Section 2, or received
//                   from a resolver).
//     vmReference — a DID URL string with a fragment, e.g.
//                   "did:example:123#key-1".
//
//   Algorithm:
//     1. The reference's bare DID (everything before the fragment) MUST equal
//        didDocument.id. If it names a different DID, this document cannot
//        speak for it — return null. (A document only describes its own id.)
//     2. Search didDocument.verificationMethod for an entry whose id equals
//        the full reference. If found, return it.
//     3. A verification method may instead be EMBEDDED inside a verification
//        relationship array rather than defined under verificationMethod.
//        Search every relationship array (authentication, assertionMethod,
//        keyAgreement, capabilityInvocation, capabilityDelegation) for an
//        embedded object (not a string reference) whose id equals the
//        reference. If found, return it.
//     4. If no match is found anywhere, return null.
//
//   String entries inside relationship arrays are references to methods
//   defined under verificationMethod; they are resolved by step 2, not by
//   step 3. Step 3 only matches embedded objects.
//
//   Why this is the sequel to Item 01: a VC-JWT issued under a DID carries a
//   key identifier (the JWS `kid`, a DID URL). The verifier resolves the
//   issuer's DID to a Document, then dereferences that kid to the exact
//   VerificationMethod — and reads publicKeyJwk to get the key it then uses
//   exactly as Item 01's verifyVcJwt used its publicKey parameter.
// ============================================================

export function dereferenceVerificationMethod(
    didDocument: DidDocument,
    vmReference: string,
): VerificationMethod | null {
    const [bareDid, fragment] = vmReference.split('#');
    if (didDocument.id !== bareDid) {
        return null;
    }

    const verificationMethod = didDocument.verificationMethod;
    if (verificationMethod !== undefined) {
        const matchingMethod = verificationMethod.find(method => method.id === vmReference);
        if (matchingMethod !== undefined) {
            return matchingMethod;
        }
    }

    return findById(vmReference, didDocument.authentication) ??
        findById(vmReference, didDocument.assertionMethod) ??
        findById(vmReference, didDocument.keyAgreement) ??
        findById(vmReference, didDocument.capabilityInvocation) ??
        findById(vmReference, didDocument.capabilityDelegation) ??
        null;
}

function findById(
    vmReference: string,
    relationship?: VerificationRelationship,
): VerificationMethod | undefined {
    if (relationship !== undefined) {
        const matchingMethod = relationship.find(
            (rel): rel is VerificationMethod => typeof rel !== 'string' && rel.id === vmReference
        );
        if (matchingMethod !== undefined) return matchingMethod;
    }

    return undefined;
}

// ============================================================
// LESSONS (read after implementing and running the tests)
// ============================================================
//
// Lesson 1 — What "decentralized" buys you, concretely
//   In Item 01 the verifier was handed "the issuer's public key the verifier
//   trusts for this issuer." That phrasing hid a hard problem: how does a
//   verifier know which key belongs to which issuer, without a central
//   authority vouching for the binding?
//
//   The classic answer is X.509: a Certificate Authority signs a certificate
//   binding a name to a key, and everyone trusts the CA. DIDs take a different
//   route. The identifier itself is derived from, or registered alongside, the
//   key material in a way that the controller — not a CA — governs. The DID
//   resolves to a DID Document the controller published; the keys in it are
//   authoritative because controlling the DID and controlling the Document are
//   the same capability under each method's rules.
//
//   This is why "did:method:id" has a method segment: each method defines its
//   own rule for how a DID maps to a Document and who is allowed to change it.
//   did:key derives the Document deterministically from the key (no registry
//   at all); did:web puts it at a well-known HTTPS URL (trust the domain);
//   did:ion anchors it on a ledger (trust the chain). Same identifier shape,
//   different root of trust — that is the "decentralized" knob.
//
// Lesson 2 — Verification methods vs verification relationships
//   A DID Document separates "here is a key" from "here is what the key is
//   allowed to do."
//
//     verificationMethod  — the catalogue of keys. Each entry has an id, a
//                           type, the controller, and the public key material
//                           (publicKeyJwk or publicKeyMultibase).
//
//     verification         — authentication, assertionMethod, keyAgreement,
//     relationships          capabilityInvocation, capabilityDelegation. Each
//                           is a list saying "these keys may be used FOR THIS
//                           PURPOSE." Entries are either a reference string
//                           pointing into verificationMethod, or an embedded
//                           key object.
//
//   The relationships are an authorization layer, not just a list. A key under
//   `authentication` proves you control the DID (logging in). A key under
//   `assertionMethod` is the one allowed to sign credentials. A VC verifier
//   should not accept a credential signed by a key that the issuer's Document
//   only lists under, say, keyAgreement — the issuer never authorized that key
//   to make assertions. Dereferencing (Section 3) finds the key; checking which
//   relationship it appears under is what authorizes its use.
//
//   Why allow both references and embedded objects? A reference keeps one
//   canonical key definition and points at it from several relationships
//   (define once, authorize for many purposes). An embedded object is for a
//   key used in exactly one relationship and nowhere else. Both are valid; a
//   reader must handle either form, which is why Section 3 searches both.
//
// Lesson 3 — DID vs DID URL, and why the distinction is load-bearing
//   A *DID* identifies a subject: did:example:123. A *DID URL* identifies a
//   resource related to that subject by adding path, query, and/or fragment:
//   did:example:123#key-1 names a specific verification method;
//   did:example:123?service=files&relativeRef=/img names something reachable
//   through a service.
//
//   The fragment is the part you will meet constantly: every verification
//   method id is the DID plus "#" plus a key name. Keeping the bare DID and
//   the fragment separate (Section 1) is what lets Section 3 ask the two
//   distinct questions a dereference is really made of: "is this resource even
//   in this document's scope?" (compare the bare DID to the document id) and
//   "which key within it?" (match the whole reference). Conflating them is how
//   you end up accepting a key from the wrong DID's document.
