# 01 — Asymmetric Crypto, Signatures, Hashing

## Overview

- **Keypair** = private key (secret) + public key (share freely). Same math, two uses.
- **Signature** = signer hashes the message, then "encrypts" the hash with their private key. Anyone with the public key can verify it.
- **Signatures prove** message integrity + that the signer holds the key. Nothing more — not freshness, not real-world identity, not confidentiality.
- **Default for VC/JWT work**: `Ed25519` (modern) or `ES256` (ECDSA over P-256, the JWT default).
- **You never roll your own crypto.** Use `node:crypto`, `libsodium`, etc.

---

## Core Concepts

### 1. The two-key idea

Every party has a **keypair**: a **private key** (kept secret) and a **public key** (shared freely). Two operations use it, in opposite directions:

- **Encrypt** — anyone encrypts with the public key; only the private-key holder can decrypt.
- **Sign** — the private-key holder signs; anyone with the public key can verify.

For DID/VC work, **you only care about signing**. Encryption is a different problem solved by different protocols.

### 2. What a signature actually is

A small blob (~64 bytes) that proves two things together:

- **Authenticity** — "the signer holds the private key"
- **Integrity** — "the message has not been altered since signing"

A message that has been altered after signing — even by a single byte — is called a **tampered** message. The integrity guarantee is what lets a verifier detect tampering: signing produces bytes bound to one exact message, so verifying against any *different* message returns `false`. This is what the lab's `tampered` parameter is for — it lets you observe that `verify(tampered, sig)` fails even though `verify(message, sig)` succeeds.

That's it. It does **not** prove:

- **Confidentiality** — the message is still readable to anyone.
- **Freshness** — someone could replay an old signed message. You need nonces/timestamps for that.
- **Real-world identity** — only that the signer holds the key. Mapping a key to a real entity is the *trust* problem, solved later by trust registries / x509 chains.

### 3. Why we sign the hash, not the message

- Signing primitives are slow and work on fixed-size input.
- A hash like SHA-256 turns any-size input into a 32-byte fingerprint.
- So the universal pattern is: `signature = sign(private_key, sha256(message))`.
- This is why **every JWT signs `base64(header) + "." + base64(payload)` as a hash**, not the raw JSON.

### 4. Hash function properties

SHA-256 is:

- **Deterministic** — same input → same output, always.
- **Fixed-size** — output is always 32 bytes.
- **One-way** — you can't recover the input from the output.
- **Collision-resistant** — practically impossible to find two inputs with the same hash.

⚠️ **SHA-256 is NOT for passwords.** Use bcrypt / argon2 for those. SHA-256 is for fingerprinting and signing.

### 5. Algorithm families

| Family | Examples | Key size | Where you'll see it |
| --- | --- | --- | --- |
| **RSA** | RS256, PS256 | 2048–4096 bits | Legacy JWTs, older TLS certs |
| **ECDSA** | ES256 (P-256), ES384 (P-384) | 256–384 bits | **JWT/VC default** — `P-256` is everywhere |
| **EdDSA** | Ed25519, Ed448 | 256 bits | Modern systems, preferred for greenfield work |

Key takeaways:

- **ECC keys are way smaller** than RSA for equivalent security. 256-bit ECC ≈ 3072-bit RSA.
- **Ed25519 > ECDSA** for greenfield work: no nonce-reuse footgun, faster, safer defaults.
- But **`ES256` (ECDSA over P-256)** is everywhere in the VC/JWT ecosystem because it's the standardized default. You'll meet both.

### 6. Named curves worth memorizing

- **`P-256`** (a.k.a. `secp256r1`, `prime256v1`) — JWT/VC default. Used by `ES256`.
- **`Curve25519` / `Ed25519`** — modern default. Used by `EdDSA`.
- **`secp256k1`** — Bitcoin/Ethereum. Appears in some `did:*` methods.

### 7. The "never roll your own" rule

You will *use* `crypto.sign` and `crypto.verify`. You will *never* implement RSA, ECDSA, or SHA-256 yourself. Side-channel attacks live in the implementation details.

---

## Self-check (answer out loud before moving on)

1. A signature proves ______ but does NOT prove ______.
2. If SHA-256 had a known collision, the threat to a JWT would be ______.
3. Ed25519 is preferred over ECDSA when ______ because ______.
4. Why does the same Ed25519 key produce the *same* signature every run, while ECDSA produces a *different* signature every run?
5. If you used `RS256` instead of `ES256`, roughly how much larger would the signature be?

---

## Optional deeper reads

Only if a concept didn't land:

- [Practical Cryptography for Developers — Asymmetric chapter](https://cryptobook.nakov.com/asymmetric-key-ciphers) — skim, skip the proofs.
- [Practical Cryptography for Developers — Digital Signatures](https://cryptobook.nakov.com/digital-signatures)
- [Cloudflare ECC primer](https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/) — only if ECC still feels mysterious.
