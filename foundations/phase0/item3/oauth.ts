/**
 * 03 — OAuth 2.0 Core (Authorization Code + PKCE)
 *
 * READ FIRST  ./oauth.notes.html  (interactive walkthrough + concepts)
 * IMPLEMENT   One function per section. Fill in each body.
 * VERIFY      npm test
 */

import {getRandomValues, hash} from 'node:crypto';

function TODO(label: string): never {
    throw new Error(`TODO — ${label} not implemented`);
}

// ============================================================
// Section 1 — Generate a PKCE code_verifier
//
//   Produce a cryptographically random `code_verifier` per RFC 7636 §4.1:
//   a string of 43–128 characters drawn from the URL-unreserved set
//   [A-Za-z0-9\-._~], regenerated freshly on each call.
// ============================================================

export function generatePkceCodeVerifier(): string {
    const rawBytes = getRandomValues(new Uint8Array(32));
    return Buffer.from(rawBytes).toString('base64url');
}

// ============================================================
// Section 2 — Derive the S256 code_challenge
//
//   Deterministic transform of a verifier into its corresponding
//   `code_challenge` for the S256 method (RFC 7636 §4.2):
//       challenge = base64url(SHA-256(ASCII(verifier)))
//   The output is a 43-character string in the base64url alphabet.
//
//   Inputs:
//     verifier — the code_verifier string (the function does not validate
//                its shape; that's the caller's job)
// ============================================================

export function deriveCodeChallenge(verifier: string): string {
    return hash('sha256', verifier, 'base64url');
}

// ============================================================
// Section 3 — Build an OAuth 2.0 authorization request URL
//
//   Construct the URL the client redirects the user to in step 2 of the
//   Authorization Code Flow with PKCE. The output preserves the
//   `authEndpoint`'s origin and pathname and appends a query string
//   carrying the OAuth parameters.
//
//   Only the parameter *keys* are transformed: camelCase input keys map
//   to snake_case on the wire (clientId → client_id, redirectUri →
//   redirect_uri, codeChallenge → code_challenge, and so on). The
//   parameter *values* travel verbatim — no transformation applied to
//   what the caller passed in.
//
//   Two parameters are not in `params` because their values are fixed
//   by the protocol: `response_type=code` and `code_challenge_method=S256`.
//   The function always emits these.
//
//   Inputs:
//     authEndpoint — absolute URL of the auth server's /authorize endpoint
//                    (e.g. "https://issuer.example.com/oauth/authorize")
//     params       — values keyed by camelCase; the keys (not the values)
//                    are converted to snake_case on the wire
// ============================================================

export function buildAuthorizationUrl(
    authEndpoint: string,
    params: {
        clientId: string;
        redirectUri: string;
        scope: string;
        state: string;
        codeChallenge: string;
    },
): string {
    const queryParams = new URLSearchParams({
        response_type: 'code',
        client_id: params.clientId,
        redirect_uri: params.redirectUri,
        scope: params.scope,
        state: params.state,
        code_challenge: params.codeChallenge,
        code_challenge_method: 'S256',
    });
    return `${authEndpoint}?${queryParams}`;
}

// ============================================================
// LESSONS (read after implementing and running `npm test`)
// ============================================================
//
// Lesson 1 — SHA-256 makes the challenge length invariant
//   No matter how long the verifier is (43 chars, 128 chars, even longer
//   in theory), the SHA-256 digest is always 32 bytes — which base64url-
//   encodes to exactly 43 characters. The auth server's storage for
//   code_challenges is therefore a fixed-size column. And brute-forcing
//   a verifier from a challenge is hopeless: 2^256 possible inputs all
//   map into the same fixed-size output space.
//
// Lesson 2 — OAuth wire-format parameter names are snake_case
//   OAuth 1.0 shipped in 2009, before camelCase had won the JSON-style
//   battle. Every parameter on the wire is snake_case: `client_id`,
//   `redirect_uri`, `response_type`, `code_challenge`,
//   `code_challenge_method`, `grant_type`. Most OAuth libraries map
//   silently between idiomatic-JS camelCase inputs and on-the-wire
//   snake_case — exactly what `buildAuthorizationUrl` is doing.
//
// Lesson 3 — The verifier–challenge pair is one-way
//   You can always compute the challenge from the verifier. You CANNOT
//   compute the verifier from the challenge — that would mean inverting
//   SHA-256. This asymmetry is the entire security property of PKCE:
//   the challenge is sent in step 2 of the flow (and is thus visible to
//   anyone watching), but only the client that holds the verifier can
//   redeem the code in step 5. An attacker who intercepts both the
//   auth-URL AND the redirect URL with the code still can't get a token,
//   because they don't have the verifier — which never left the client.
