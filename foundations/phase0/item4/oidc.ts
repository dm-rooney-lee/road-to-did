/**
 * 04 — OpenID Connect (ID Token + nonce + the `openid` scope)
 *
 * READ FIRST  ./oidc.notes.html  (what OIDC adds on top of OAuth; interactive demos)
 * IMPLEMENT   One function per section. Fill in each body.
 * VERIFY      npx tsx --test foundations/phase0/item4/oidc.test.ts
 *
 * Item 04 builds directly on Items 02 (JWS) and 03 (OAuth). The crypto and the
 * authorize-URL plumbing are already done. The new material here is *claim
 * discipline* — what makes an ID Token an ID Token rather than an arbitrary JWT,
 * and what a relying party actually checks before trusting one.
 */

import {type KeyObject} from 'node:crypto';

function TODO(label: string): never {
    throw new Error(`TODO — ${label} not implemented`);
}

// ============================================================
// Section 1 — Mint an OIDC ID Token
//
//   Issue an ID Token: a compact JWS (ES256) whose payload is the OIDC
//   claim set. The header is fixed: { alg: 'ES256', typ: 'JWT' }. The
//   claims object is the JWS payload, used verbatim — no transformation,
//   no defaulting of missing fields.
//
//   Inputs:
//     privateKey — EC P-256 private KeyObject (the issuer's signing key)
//     claims     — the ID Token claim set; passes through unchanged
//
//   Returns: the compact JWS string `header.payload.signature`.
//
//   The five claims an OIDC ID Token MUST carry (RFC OIDC Core §2):
//     iss — issuer identifier (URL of the OP)
//     sub — subject (stable identifier for the end-user at this issuer)
//     aud — audience (the client_id of the RP this token is for)
//     exp — expiry, Unix seconds
//     iat — issued at, Unix seconds
//   Optional but standard in real flows:
//     nonce — value the RP sent in the auth request; binds this token
//             to that specific request
//
//   This function does NOT validate the claims object — it's the caller's
//   responsibility to assemble a correct one. (Validation lives on the
//   verifying side; see Section 2.)
// ============================================================

export function mintIdToken(
    privateKey: KeyObject,
    claims: Record<string, unknown>,
): string {
    return TODO('mintIdToken');
}

// ============================================================
// Section 2 — Verify an OIDC ID Token
//
//   Decide whether to trust an incoming ID Token. The function decodes
//   the token, runs the signature check, then runs the OIDC claim checks
//   against the expectations the RP supplies.
//
//   Inputs:
//     idToken      — compact JWS produced by some issuer
//     publicKey    — EC P-256 public KeyObject the RP trusts for this issuer
//     expectations — what THIS relying party requires from a valid token:
//                      issuer     — exact match against payload.iss
//                      audience   — must appear in payload.aud (which may be
//                                   a string OR an array of strings)
//                      nonce      — if present, must match payload.nonce
//                                   exactly; if absent, payload.nonce is
//                                   not checked
//                      now        — current time in Unix seconds, used to
//                                   evaluate payload.exp; supplied by the
//                                   caller so tests are deterministic
//
//   Return shape (every field populated on every call):
//     valid  — true only if signature verifies AND every claim check passes
//     claims — the decoded payload (returned regardless of validity, so
//              the caller can inspect what was claimed)
//     reason — when valid is false, identifies the FIRST check that failed,
//              one of: 'signature' | 'iss' | 'aud' | 'exp' | 'nonce' | 'sub'.
//              Undefined when valid is true.
//
//   Check order (short-circuits on the first failure):
//     1. signature  (alg discipline + cryptographic verify — Item 02)
//     2. iss        (must equal expectations.issuer)
//     3. aud        (must contain expectations.audience)
//     4. exp        (must be strictly greater than expectations.now)
//     5. nonce      (only if expectations.nonce was supplied)
//     6. sub        (must be present and non-empty)
// ============================================================

export type IdTokenExpectations = {
    issuer: string;
    audience: string;
    nonce?: string;
    now: number;
};

export type IdTokenVerifyResult = {
    valid: boolean;
    claims: Record<string, unknown>;
    reason?: 'signature' | 'iss' | 'aud' | 'exp' | 'nonce' | 'sub';
};

export function verifyIdToken(
    idToken: string,
    publicKey: KeyObject,
    expectations: IdTokenExpectations,
): IdTokenVerifyResult {
    return TODO('verifyIdToken');
}

// ============================================================
// Section 3 — Build an OIDC authorization request URL
//
//   Construct the URL the RP redirects the user to in step 2 of the
//   Authorization Code Flow, with OIDC layered on top: the `scope` MUST
//   include the literal token `openid` (this is what asks the OP to
//   return an ID Token), and a `nonce` query parameter is added.
//
//   The function does NOT reformat the scope — it passes through whatever
//   the caller supplies. Ensuring `openid` is in there is the caller's
//   responsibility. (This matches how real OIDC libraries behave; the
//   server will reject the request if `openid` is missing.)
//
//   Inputs:
//     authEndpoint — absolute URL of the OP's /authorize endpoint
//     params       — same shape as Item 03's buildAuthorizationUrl, plus
//                    `nonce`. Keys are camelCase at the function boundary;
//                    on the wire they become snake_case (see Item 03 Lesson 2).
//
//   The OIDC-specific delta over Item 03's OAuth-only function:
//     • scope must include `openid` (caller-enforced)
//     • a `nonce` query parameter is added
//   Everything else (`response_type=code`, `code_challenge_method=S256`,
//   `client_id`, `redirect_uri`, `state`, `code_challenge`) is unchanged.
// ============================================================

export function buildOidcAuthorizationUrl(
    authEndpoint: string,
    params: {
        clientId: string;
        redirectUri: string;
        scope: string;
        state: string;
        nonce: string;
        codeChallenge: string;
    },
): string {
    return TODO('buildOidcAuthorizationUrl');
}

// ============================================================
// LESSONS (read after implementing and running the tests)
// ============================================================
//
// Lesson 1 — `openid` in scope is the trigger
//   OAuth 2.0 gives you an access token. OIDC gives you, in addition, an
//   ID Token — but only if you ask. The single signal that asks is the
//   literal string `openid` in the `scope` parameter of the authorization
//   request. Without it, the OP runs a plain OAuth flow and never mints
//   an ID Token, no matter what other claims-related parameters you send.
//   With it, the OP returns an ID Token alongside the access token.
//
//   This is why OIDC is described as "an identity layer on top of OAuth":
//   the wire format is OAuth's; the new identity surface is opted into by
//   one scope token.
//
// Lesson 2 — `nonce` and `state` look similar but defend different attacks
//   Both are opaque, random, client-generated values sent in the auth
//   request. They protect against different things and live in different
//   places at the end of the round trip:
//
//     state — sent in /authorize, ECHOED back on the redirect URL. The RP
//             compares the echoed value to what it stored for this browser
//             session. Defends against CSRF: an attacker who tricks your
//             browser into hitting a forged callback URL won't have a
//             matching state. State lives only on the wire — never inside
//             the ID Token.
//
//     nonce — sent in /authorize, EMBEDDED in the ID Token claims by the
//             OP. The RP compares payload.nonce to what it stored for this
//             auth request. Defends against ID-Token replay: an attacker
//             who captures a valid ID Token from one session can't replay
//             it into a new RP session, because the nonce in the token
//             won't match the new session's nonce.
//
//   Mnemonic: state defends the redirect; nonce defends the token.
//
// Lesson 3 — ID Token and Access Token have different audiences
//   They look alike (both can be JWTs) but they're for different readers:
//
//     ID Token     — `aud` is the client_id. The RP reads it, verifies
//                    it, learns who the user is. The ID Token is FOR THE
//                    CLIENT and is not meant to be forwarded anywhere.
//
//     Access Token — opaque to the client. The client just forwards it to
//                    a resource server (e.g. /userinfo). Its audience is
//                    the resource server, not the client. If it happens
//                    to be a JWT, the resource server verifies it; the
//                    client should not introspect it.
//
//   This matters for security: if you verify an Access Token *as if it
//   were an ID Token* (checking aud = your client_id), you'll accept
//   tokens that were never issued for you. The two are not interchangeable.
