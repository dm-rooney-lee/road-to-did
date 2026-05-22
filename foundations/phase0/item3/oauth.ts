/**
 * 03 — OAuth 2.0 Core (Authorization Code + PKCE)
 *
 * READ FIRST  ./oauth.notes.md
 * IMPLEMENT   One function per section. Fill in each body.
 * VERIFY      npm test
 */

function TODO(label: string): never {
    throw new Error(`TODO — ${label} not implemented`);
}

// ============================================================
// Section 1 — Generate a PKCE code_verifier
//
//   Produce a cryptographically random, URL-unreserved string suitable as
//   a PKCE `code_verifier` (RFC 7636 §4.1).
//
//   1a. verifier length is between 43 and 128 characters (inclusive)
//   1b. verifier uses only PKCE-unreserved characters: [A-Za-z0-9\-._~]
//   1c. each call returns a fresh value (driven by cryptographic randomness,
//       not a counter or fixed seed)
// ============================================================

export function generatePkceCodeVerifier(): string {
    TODO('generatePkceCodeVerifier');
}

// ============================================================
// Section 2 — Derive the S256 code_challenge
//
//   Compute the PKCE `code_challenge` for the S256 method (RFC 7636 §4.2):
//      challenge = base64url(SHA-256(ASCII(verifier)))
//
//   Inputs:
//     verifier — the code_verifier string from Section 1 (the function
//                does not validate its shape; that's the caller's job)
//
//   2a. challenge length is exactly 43 characters
//       (SHA-256 → 32 bytes → 43 base64url chars, no padding)
//   2b. challenge uses only base64url characters: [A-Za-z0-9_-]
//   2c. deterministic — the same verifier always yields the same challenge
// ============================================================

export function deriveCodeChallenge(verifier: string): string {
    TODO('deriveCodeChallenge');
}

// ============================================================
// Section 3 — Build an OAuth 2.0 authorization request URL
//
//   Construct the URL the client redirects the user to in step 2 of the
//   Authorization Code Flow with PKCE.
//
//   Inputs:
//     authEndpoint — absolute URL of the auth server's /authorize endpoint
//                    (e.g. "https://issuer.example.com/oauth/authorize")
//     params       — camelCase inputs; the function maps each to the
//                    corresponding snake_case query parameter on the wire
//
//   3a. result preserves the authEndpoint's origin and pathname
//   3b. response_type=code is always set
//   3c. code_challenge_method=S256 is always set
//   3d. every camelCase input becomes a snake_case query parameter with
//       the same value:
//         clientId      → client_id
//         redirectUri   → redirect_uri
//         scope         → scope
//         state         → state
//         codeChallenge → code_challenge
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
    TODO('buildAuthorizationUrl');
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
