# 03 — OAuth 2.0 Core (Authorization Code + PKCE)

## Overview

- OAuth 2.0 is a **delegated authorization** protocol: it lets a client (your app) get permission to act on a user's behalf at another service, without the user handing over their password.
- OAuth is **NOT** an authentication protocol on its own. The identity layer that sits on top of OAuth is **OpenID Connect** (next item).
- The flow you must internalize: **Authorization Code Flow with PKCE** — the modern, web- and mobile-safe variant.
- **PKCE** (pronounced "pixy") is a small extension that binds the code-exchange step to a per-request secret the client never reveals over the network — defending against authorization-code interception.
- **Where you'll meet OAuth in DID/VC:** OpenID4VC (Issuance + Presentation) is built directly on OAuth 2.0. Every wallet ↔ issuer flow you touch later in this roadmap is an OAuth flow under the hood.

---

## Where you'll see each piece

| Term | What it is | Where it shows up | Do you touch it directly? |
|---|---|---|---|
| **Authorization Code Flow** | The canonical multi-step token exchange | OpenID Connect, OpenID4VCI, basically every "Sign in with X" | Yes — you build the URLs, parse the callbacks |
| **PKCE** | `verifier` + `challenge` pair preventing code interception | Mandatory in OAuth 2.1 and OpenID4VCI; mandatory for all public clients (mobile, SPA) | Yes — every secure client generates one per session |
| **state** | Opaque CSRF token | Every authorization request | Yes — you generate it and verify it on callback |
| **`/authorize` endpoint** | Server-side login + consent UI | URL query-string protocol | Indirect — you redirect to it |
| **`/token` endpoint** | Code-for-token exchange | `POST` with form-encoded body | Yes — direct backend call |
| **Access / Refresh tokens** | Bearer credentials returned by `/token` | Sent in `Authorization: Bearer …` headers | Yes |

---

## Core Concepts

### 1. The four OAuth roles

| Role | Real-world example | Map to OpenID4VC |
|---|---|---|
| **Resource Owner** | The user | Credential subject (still the user) |
| **Client** | The app requesting access | Wallet |
| **Authorization Server** | Issues tokens | Credential issuer's auth endpoint |
| **Resource Server** | Hosts protected resources | Credential endpoint |

Memorize the labels — every spec assumes you know them.

### 2. The Authorization Code Flow with PKCE — step by step

Who creates each value, when it travels, on which channel, what each party stores and does on receipt. Memorize this — every OAuth-based protocol downstream (OIDC, OpenID4VCI, OpenID4VP) is a variation of it.

#### Step 1 — Client-side prep (no network call yet)

The client (your app / wallet) generates **three values locally**:

| Value | What it is | Where it lives |
|---|---|---|
| `code_verifier` | Random 43–128 char URL-unreserved string | **In client memory ONLY. Never sent in step 2.** |
| `code_challenge` | `base64url(SHA-256(code_verifier))` — derived from verifier | Will be sent in step 2 (browser URL). |
| `state` | Random opaque CSRF token (16+ bytes recommended) | Stored locally; will be sent in step 2 and verified by the client in step 4. |

Crucial: the **verifier never leaves the client until step 5 (back-channel)**. Only the **hash** of it (the challenge) goes out in step 2. This is the entire foundation of why interception is safe — see §3 below.

#### Step 2 — Authorization request  (FRONT-CHANNEL: browser)

Client builds a URL and **redirects the user's browser** to it:

```
GET https://auth.example.com/authorize?
    response_type=code           # "I want a code, not a token"
    &client_id=wallet-app-42     # who the client is (pre-registered with the AS)
    &redirect_uri=...            # where to send the code back
    &scope=openid email          # what permissions I'm asking for
    &state=xyz-csrf-abc          # CSRF token, will be echoed back
    &code_challenge=E9M...wcM    # the HASH (verifier is NOT here)
    &code_challenge_method=S256  # which transform produced the challenge
```

So: `code_challenge`, `code_challenge_method`, and `state` all ride along as **query parameters in the URL the browser is redirected to**. They're visible to anyone watching the browser channel.

**Auth server, on receipt:**

1. Looks up `client_id`. Reject if unknown.
2. Verifies `redirect_uri` matches one pre-registered for that `client_id`. Reject otherwise.
3. Verifies `scope` is permitted for that client.
4. **Stores in a server-side session** (keyed by a cookie or transient session id): `client_id`, `redirect_uri`, `scope`, **`code_challenge`**, `code_challenge_method`, `state`.
5. Renders the login + consent page to the user.

**Note: the auth server stores the challenge. It does NOT see the verifier — and won't, until step 5.**

#### Step 3 — User logs in and consents  (off-protocol)

User types credentials into the auth server's login page, sees a consent screen ("Wallet App wants: openid, email — Allow?"), clicks Allow. This is browser ↔ auth server only; the client app isn't involved.

On success, the auth server:
1. Mints an **authorization code** — random opaque string, short-lived (60s typical), single-use.
2. Associates the code with the session it stored in step 2 — so the code is bound to `code_challenge`, `redirect_uri`, granted scopes, and the authenticated user.

#### Step 4 — Authorization response  (FRONT-CHANNEL: browser)

Auth server tells the browser to redirect to the client's `redirect_uri`:

```
302 Location: https://wallet.example.com/callback?
    code=SplxlOBeZQQYbYS6WxSbIA   # the authorization code
    &state=xyz-csrf-abc           # echoed UNCHANGED from step 2
```

**Client, on receipt:**

1. **Verifies returned `state` === stored `state`.** Mismatch → reject; someone tried to inject a foreign flow's code into this session (CSRF — see §4).
2. Has the code in hand. The code alone is useless — it must be exchanged for tokens in step 5.

#### Step 5 — Token request  (BACK-CHANNEL: direct client → auth server)

This step does **NOT** go through the browser. The client makes a direct HTTP call (from its backend server for confidential clients, from JS for SPAs/native apps):

```
POST https://auth.example.com/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https://wallet.example.com/callback
&client_id=wallet-app-42
&code_verifier=dBjf...VEU        # FIRST TIME the verifier appears on the wire
```

**Auth server, on receipt (validation runs in this order — fail fast on any check):**

1. **Authenticate the client.**
   - *Confidential clients* (with `client_secret`): verify the secret via HTTP Basic Auth or request body. RFC 6749 §3.2.1 *requires* this happen for confidential clients before anything else.
   - *Public clients* (SPAs, mobile — no secret): sanity-check that `client_id` is a known registered client. The substantive client-authentication for public clients is PKCE in step 4 below.
2. **Look up the `code`** in storage. Reject if unknown, expired, or already redeemed.
3. **Check the code was issued to *this* client.** The code was bound to a `client_id` when minted in step 3 of the overall flow. If the request's `client_id` ≠ the bound `client_id` → reject. (A code issued to client A must never be redeemable by client B.)
4. **Verify PKCE.** Compute `expected = base64url(SHA-256(submitted_code_verifier))`. Compare with the `code_challenge` stored in step 2. Mismatch → reject.
5. **Verify `redirect_uri`** matches what was sent in step 2 of the overall flow. Mismatch → reject.
6. **Mark the code as redeemed** (single-use enforcement).
7. **Mint the access token** (+ optional refresh token).

#### Step 6 — Token response  (back-channel)

Auth server returns JSON (yes, the *response* is JSON — even though the *request* in step 5 was form-encoded):

```
200 OK
Content-Type: application/json

{
    "access_token": "eyJ...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "tGzv3JOkF0XG5Q...",
    "scope": "openid email"
}
```

Client now has tokens.

---

### 3. PKCE — why interception is safe (the two-channel argument)

Now that you've seen the full flow, here's why an attacker who intercepts the browser channel still cannot redeem the code.

**Two channels:**

| Channel | Who sees it | Steps |
|---|---|---|
| **Front-channel (browser)** | User-agent, URL bars, OS deep-link routing, browser history, server logs, Referer headers | 2, 3, 4 |
| **Back-channel (direct HTTPS)** | Only the client and the auth server | 5, 6 |

**What an attacker watching the browser channel sees:**
- Step 2: `code_challenge` (the SHA-256 hash of the verifier) + `state`.
- Step 4: the `code`.

**What the attacker does NOT see:**
- The `code_verifier`. It only appears in step 5 — the back-channel — and exists only in client memory before that.

**Can the attacker redeem the stolen code?** They'd need to POST `/token` with `grant_type`, the stolen `code`, AND a `code_verifier`. They have:
- `code` ✓ (intercepted in step 4)
- `code_verifier` ✗ — they only saw the *hash* (challenge). To recover the verifier from the challenge they'd have to invert SHA-256, which is computationally infeasible.

The auth server's step-5 check (`SHA-256(submitted_verifier) === stored_challenge`) fails. The code is rejected.

**That's the entire security argument.** PKCE binds code-redemption to a per-flow secret (`code_verifier`) that **travels on a different channel** than the code.

**Real attack scenarios PKCE defends against:**
- **Mobile deep-link hijacking** — a malicious app registers the same custom URL scheme (e.g. `myapp://callback`) as your wallet. The OS hands the redirect to whichever app responds. Without PKCE, the malicious app receives the code and redeems it.
- **Browser history / log exfil** — auth codes in URLs end up in browser history, server access logs, Referer headers sent to third-party resources on the callback page.
- **Network observer on the user's device** — even with TLS to the auth server, the OS sees the redirect URL.

In every one of these, the attacker sees the code but NOT the verifier (which never left your app's memory).

**Why `code_challenge_method=plain` is forbidden in practice:**
The spec allows `plain` where `code_challenge` equals `code_verifier` (no hashing). In that case the attacker who intercepts step 2 has both the challenge AND a directly-usable verifier — PKCE is defeated. Modern profiles (OAuth 2.1, OpenID4VC, OpenID Connect FAPI) mandate `S256`.

---

### 4. The `state` parameter — CSRF protection (front-channel only)

`state` lives **as a query parameter** in the same authorization URL where `code_challenge` lives (step 2), and is echoed back as a query parameter on the callback URL (step 4). Two key differences from PKCE:

- The auth server doesn't *interpret* `state` — it just passes it through unchanged.
- The *client* validates `state`, not the server.

**Lifecycle (already in the flow above; restated):**

1. Client generates random `state` before step 2.
2. Client stores `state` locally (session storage, encrypted cookie, etc.).
3. Client sends `state` in the authorization URL query (step 2).
4. Auth server echoes `state` unchanged in the callback URL query (step 4).
5. **Client verifies returned `state` === stored `state`.** Reject if not.

**Attack it defends against — login CSRF:**

Without `state`:
1. Attacker initiates their own auth flow against the AS, obtains an authorization code for *the attacker's* account.
2. Attacker tricks the victim into visiting `https://wallet.example.com/callback?code=ATTACKERS_CODE`.
3. The wallet thinks "I got a callback, let me exchange this code" — exchanges it, gets tokens bound to the **attacker's** identity.
4. The victim is now logged in as the attacker. The victim sees the attacker's data, and anything the victim does going forward is observable by the attacker as that account.

With `state`: in step 3, the wallet checks `state`. The attacker can't guess the random value the wallet generated for THIS user's session, so the callback fails immediately.

**`state` vs `code_challenge` — easy to confuse:**

| | What it protects against | Validated by | Travels on |
|---|---|---|---|
| `state` | Login CSRF (foreign code injected into your flow) | The **client** (in step 4) | Browser channel only — sent in step 2, echoed in step 4 |
| `code_challenge` | Authorization code interception | The **auth server** (in step 5) | Browser channel in step 2; the matching verifier travels on the back-channel in step 5 |

In OpenID Connect / OpenID4VC you'll also meet a `nonce` parameter — that's CSRF for the *ID Token*, with a similar shape to `state` but checked against the token rather than the redirect URL.

### 5. Token types

| Token | Lifetime | Carries | Sent where |
|---|---|---|---|
| **Authorization code** | Seconds (60s typical) | Opaque, single-use | `POST /token` |
| **Access token** | Minutes–hours | The actual permission | `Authorization: Bearer <token>` to resource server |
| **Refresh token** | Days–months | Long-lived re-grant material | Back to `/token` to mint a new access token |

In OpenID Connect, you additionally get an **ID token** (a JWT — exactly the JWS you just built in Item 02!) that carries identity claims.

In OpenID4VC, what you ultimately receive is a **verifiable credential** in place of (or alongside) the access token.

### 6. URL encoding details

Two wire formats; both are the same encoding (`application/x-www-form-urlencoded`), just in different places:

- **Authorization request** — `GET /authorize?<query-string>`. Parameters in the URL query.
- **Token request** — `POST /token` with body `application/x-www-form-urlencoded`. Same key=value&… encoding, just in the body. Not JSON.

All OAuth parameter names are **snake_case** (`client_id`, `code_challenge`, `redirect_uri`, `code_challenge_method`, `grant_type`). JavaScript conventions are camelCase; the wire format predates that fight.

### 7. Where this slots into the DID/VC roadmap

| Phase | What's built on OAuth |
|---|---|
| **Item 04** | OpenID Connect — identity layer adds ID Token (JWT) + `/userinfo` |
| **Phase 3** | OpenID4VCI — credential issuance is an OAuth grant |
| **Phase 3** | OpenID4VP — credential presentation reuses the OAuth request shape |
| **Phase 3** | DPoP — binds an OAuth access token to a key (sender-constrained) |

If you understand Authorization Code + PKCE, you understand the skeleton of every credential exchange protocol coming later.

---

## Self-check (answer out loud)

1. What does PKCE protect against, and why isn't TLS (HTTPS) alone enough?
2. `code_verifier` and `code_challenge` are mathematically related but only one is secret. Which, and why?
3. Why is `state` validated by the *client*, not the auth server?
4. What's the wire format for both the auth request query string AND the token request body? Why isn't either of them JSON?
5. In the OpenID4VC mapping, who plays each of the four OAuth roles?
6. If `code_challenge_method=plain` is in a spec, why should you still reject it in production code?

---

## Optional deeper reads

- [RFC 6749 — OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) — the foundational spec. Long; §1–§5 are the canon.
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636) — short and sharp; includes the §B.1 test vector you'll use in Section 2.
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700) — the modern "what's actually safe."
- [OAuth 2.1 draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) — consolidates BCPs; deprecates the implicit flow; makes PKCE mandatory for ALL clients.
