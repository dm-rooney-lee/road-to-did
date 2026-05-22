# 02 — JWT Family (JWT, JWS, JWA, JWK, & JWE in passing)

## Overview

- A **JWT** is a JSON claims set wrapped as a **JWS** (signed) or, rarely, a **JWE** (encrypted). In DID/VC work, *JWT ≈ JWS* — assume JWS unless told otherwise.
- **Compact serialization** is the dotted URL-safe form: `base64url(header).base64url(payload).base64url(signature)`.
- **JWA** is just the algorithm registry. `ES256` = ECDSA over P-256 + SHA-256 — exactly what you implemented in Item 01.
- **JWK** is the JSON representation of a (public or private) key. The same P-256 key from Item 01, written as `{kty:"EC", crv:"P-256", x:..., y:...}`.
- The whole family's biggest footgun is the `alg` header. A verifier that *trusts* `header.alg` instead of *enforcing an expected* algorithm can be bypassed with `{"alg":"none"}`.

---

## Core Concepts

### 1. JWT vs JWS vs JWE

| Term | Spec | What it is |
| --- | --- | --- |
| **JWT** | RFC 7519 | A JSON claims set packaged inside either a JWS or a JWE. |
| **JWS** | RFC 7515 | Signed payload. Three parts: `header.payload.signature`. *Almost every JWT you'll meet in VC/DID work is a JWS.* |
| **JWE** | RFC 7516 | Encrypted payload. Five parts. Rare in identity protocols. |
| **JWA** | RFC 7518 | Algorithm registry. Maps short names → crypto: `ES256`, `RS256`, `EdDSA`, `HS256`, … |
| **JWK** | RFC 7517 | JSON serialization of a key (public or private). |

In conversation, "JWT" is shorthand for "compact JWS containing a JSON claims set." Strictly, the JWT is the *claims*; the JWS is the *envelope*. Don't get hung up on the distinction — but know that "verifying a JWT" really means "verifying the JWS that wraps it."

### 2. The compact JWS

```
base64url(header) . base64url(payload) . base64url(signature)
```

- Three URL-safe segments joined by `.`.
- The **signing input** is the ASCII string `base64url(header) + "." + base64url(payload)` — exactly that, including the dot, before the third segment exists.
- The signature is over those bytes, not over the original JSON. Implementations differ on whitespace and key order; signing the encoded form is what makes it deterministic.

### 3. base64url

- Standard **base64** uses `+`, `/`, and `=` padding. None of those are URL-safe (`+` becomes space in query strings, `/` is a path separator, `=` is reserved).
- **base64url** swaps `+ → -`, `/ → _`, and drops `=` padding.
- Node has it built in: `buf.toString('base64url')` and `Buffer.from(s, 'base64url')`.

### 4. The header

Minimum useful header:

```json
{ "alg": "ES256", "typ": "JWT" }
```

- **`alg`** — algorithm. *Verifiers must enforce an expected `alg`*, not pick a verifier based on the header. (See concept 9.)
- **`typ`** — usually `"JWT"`, but profile-specific values exist (`"vc+sd-jwt"`, `"dpop+jwt"`, `"openid4vci-proof+jwt"`, …).
- **`kid`** — optional key identifier. Lets a verifier pick the right public key from a JWK Set.

### 5. Registered claims (RFC 7519 §4.1)

Standard claims, three-letter, lowercase:

| Claim | Meaning |
| --- | --- |
| `iss` | issuer |
| `sub` | subject (who the token is *about*) |
| `aud` | audience (who it's *for*) |
| `exp` | expiry (**Unix seconds, not milliseconds**) |
| `nbf` | not before |
| `iat` | issued at |
| `jti` | JWT ID (unique nonce) |

All are optional; pick what your protocol needs. **`exp` is seconds, not milliseconds** — losing a `1000` divisor is a classic bug that leaves tokens valid for thousands of years.

### 6. JWA — the algorithms you'll meet

| Name | Crypto | Where |
| --- | --- | --- |
| `ES256` | ECDSA P-256 + SHA-256 | **JWT/VC default**; the algorithm you built in Item 01 |
| `EdDSA` | Ed25519 | Modern OpenID4VC, `did:key`, newer profiles |
| `RS256` | RSA-2048+ + SHA-256 | Legacy OIDC (Google OAuth, Auth0 defaults) |
| `HS256` | HMAC-SHA256 (symmetric) | Session tokens with a shared secret — **never** for VC |
| `none` | no signature | Attack vector. See concept 9. |

For DID/VC, you'll mostly see `ES256` and `EdDSA`.

### 7. ECDSA signature format — DER vs JOSE raw

This one bites everybody once.

- Node's default `crypto.sign('sha256', msg, ecKey)` returns a **DER-encoded** ECDSA signature: 70–72 bytes of ASN.1 with length prefixes.
- **JWS requires raw `R∥S` concatenation** (RFC 7518 §3.4): for P-256, exactly **64 bytes** — the two 32-byte big integers laid end-to-end, no framing.

To switch Node into JOSE form, pass `dsaEncoding: 'ieee-p1363'` to `sign`/`verify`. Forget it and your token will look fine in [jwt.io](https://jwt.io/) but real verifiers (browsers, other-language libraries) will reject the signature with no obvious clue why.

### 8. JWK — keys as JSON

A public P-256 key as a JWK:

```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
}
```

- `kty` — key type (`EC`, `RSA`, `OKP`)
- `crv` — curve name (P-256, Ed25519, …) for EC/OKP
- `x`, `y` — curve point coordinates, **base64url-encoded big-endian bytes**
- For *private* keys, add `d` (also base64url)

A **JWK Set** (JWKS) bundles multiple keys, conventionally published at `/.well-known/jwks.json`. Verifiers fetch the issuer's JWKS, pick the right key by `kid`, and verify.

### 9. The `alg: none` attack and verifier discipline

In 2015 ([Auth0 disclosure](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)) it came out that several mainstream JWT libraries trusted the `alg` field in the *attacker-controlled* header and dispatched accordingly:

- `alg: 'ES256'` → run ECDSA verify
- `alg: 'none'`   → return `true` (skip verification entirely)

Attacker sends `alg: 'none'` with an empty signature, library returns "valid", payload is trusted. Game over.

Variant: **algorithm confusion.** A token signed `ES256` (public key known) is replayed with `alg: 'HS256'`. If the verifier uses HMAC-SHA256 with the issuer's *public* key as the symmetric secret (the public key really is public, so the attacker can compute the same HMAC), the verifier accepts.

Both attacks share **one fix**: the verifier knows what algorithm it expects. Reject anything else. Never use `header.alg` to *choose* the verifier — use it only to *match* against the expected value.

A correct verifier:

1. Splits on `.`, base64url-decodes header and payload.
2. **Checks `header.alg` equals the expected algorithm.** Reject otherwise.
3. Looks up the public key (by `iss` or `kid`).
4. Recomputes the signing input (`encodedHeader.encodedPayload`) and verifies the signature with that key.
5. Checks `exp`, `nbf`, `aud`, `iss` if applicable.

Step 2 is the most subtly important.

### 10. JWE in one paragraph

JWE wraps an encrypted payload. Five compact parts: `header.encryptedKey.iv.ciphertext.tag`. The header carries `alg` (how the content key was wrapped — RSA-OAEP, ECDH-ES, …) and `enc` (how the content was encrypted, usually `A256GCM`). You rarely see JWE in DID/VC core flows — credential confidentiality is more often handled at the transport (TLS) or via selective disclosure (SD-JWT) rather than encrypting the credential itself.

---

## Self-check (answer out loud before moving on)

1. A "JWT" is technically two things stacked. What wraps what?
2. Why does the verifier compute the signature over `base64url(header) + "." + base64url(payload)` instead of over the raw JSON?
3. What attack does `{"alg": "none"}` enable, and what one rule kills it?
4. What does `exp: 1758000000` mean — and what bug do you create if you confuse it with milliseconds?
5. Given a JWK with `kty: "EC"`, `crv: "P-256"`, `x`, `y` — how does that JSON correspond to the public key bytes of an ECDSA P-256 keypair you generated in Item 01?
6. Two JWTs signed with the same ES256 key over the same payload — will their signature segments be byte-equal? Why or why not? *(Hint: re-read Item 01, lesson 1.)*
7. If you signed a JWT with Node's default `sign('sha256', ..., key)` and a browser verifier rejected it, what's the most likely cause?

---

## Optional deeper reads

- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519) — the JWT spec. ~25 pages, readable.
- [RFC 7515 — JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515) — the envelope spec.
- [RFC 7518 §3.4 — ECDSA in JWA](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4) — the raw `R∥S` encoding rule.
- [Auth0 — Critical vulnerabilities in JSON Web Token libraries (2015)](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) — the `alg: none` and algorithm-confusion history.
- [jwt.io](https://jwt.io/) — paste a token, see it decoded. (It does NOT validate `alg`; useful for inspection only.)
