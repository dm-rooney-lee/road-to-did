# Roadmap

Bottom-up: each phase is a prerequisite for the next, so don't skip. Mark `[ ]` → `[x]` as you finish an item.

## Phase 0 — Foundations (crypto & web identity)

Without these, every layer above looks like magic.

- [x] **Asymmetric crypto / signatures / hashing** — RSA vs ECDSA vs EdDSA, SHA-256, and what signature verification actually guarantees
- [x] **JSON Web Token family** — JWT, JWS, JWE, JWA, JWK — [jwt.io](https://jwt.io/), [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [x] **OAuth 2.0 core** — Authorization Code Flow, PKCE, token types
- [x] **OpenID Connect** — how an identity layer sits on top of OAuth
- [x] **CBOR / COSE** — the binary cousins of JSON/JWS; required for mdoc — [RFC 8949](https://datatracker.ietf.org/doc/html/rfc8949), [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052)

## Phase 1 — Decentralized identity concepts

The SSI (Self-Sovereign Identity) triangle — **Issuer ↔ Holder ↔ Verifier** — is the picture to internalize.

- [x] **W3C VC Data Model 2.0** — what a verifiable credential *is* conceptually — [spec](https://www.w3.org/TR/vc-data-model-2.0/)
- [x] **W3C DID Core** — `did:method:identifier` syntax, DID Document structure — [spec](https://www.w3.org/TR/did-core/)
- [ ] **Major DID methods compared** — be able to explain at least four: *(in progress)*
  - `did:key` (self-contained, simplest)
  - `did:web` (domain-based, most practical)
  - `did:jwk` (JWK wrapped as a DID)
  - `did:ion` / `did:ebsi` (ledger-anchored)
- [ ] **DID Resolution** — how you go from a DID string to its DID Document
- [ ] **Why eIDAS uses x509 instead of DID identifiers** — understand the trade-off

## Phase 2 — Credential formats

The same VC concept, different envelopes. Two camps coexist.

- [ ] **SD-JWT** — how Selective Disclosure JWT builds partial disclosure from a hash tree — [draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- [ ] **SD-JWT VC** — the IETF profile expressing a VC as an SD-JWT — [draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
- [ ] **Read a reference SD-JWT implementation** — see what real code looks like — [openwallet-foundation/sd-jwt-js](https://github.com/openwallet-foundation/sd-jwt-js)
- [ ] **ISO/IEC 18013-5 mDL/mdoc overview** — CBOR-based envelope + offline transport
- [ ] **mdoc device engagement** — how the QR/NFC/BLE handshake works
- [ ] **Holder Binding (Key Binding)** — proving the person holding a credential is *actually* its subject

## Phase 3 — Exchange protocols (OpenID4VC family)

How credentials are *handed back and forth*.

- [ ] **OpenID4VCI** — credential issuance — [spec](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
  - [ ] Draw the Authorization Code Flow yourself
  - [ ] Draw the Pre-Authorized Code Flow yourself
  - [ ] Roles of Credential Offer, Credential Endpoint, Deferred Endpoint
- [ ] **OpenID4VP** — credential presentation — [spec](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
  - [ ] Presentation Request → Response flow
  - [ ] Same-device vs cross-device flows
- [ ] **DCQL (Digital Credentials Query Language)** — the newer presentation query syntax
- [ ] **Presentation Exchange (PEX)** — the prior generation, still widely used
- [ ] **W3C Digital Credentials API** — browser-native integration, landing in Chrome

## Phase 4 — Trust infrastructure

Signatures alone aren't enough: "is this issuer actually authorized?", "is this credential still alive?"

- [ ] **Trust Registry / Trusted List** — how eIDAS Trusted Lists work
- [ ] **x509 certificate chains** — verifying an issuer key up to a root
- [ ] **W3C Bitstring Status List** — privacy-preserving revocation — [spec](https://www.w3.org/TR/vc-bitstring-status-list/)
- [ ] **Short-lived credential pattern** — fast expiry as an alternative to revocation
- [ ] **Audit logging requirements** — what log retention regulations expect

## Phase 5 — Profiles & regulatory context

Specs are flexible; real deployments narrow them through profiles.

- [ ] **HAIP 1.0** — how it constrains OpenID4VC to achieve interop — [spec](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)
- [ ] **EUDI ARF (Architecture and Reference Framework)** — the EU's official blueprint — [repo](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework)
- [ ] **eIDAS 2.0** — at least Article 5a (Wallet) and Article 6a (use cases)
- [ ] **GDPR data minimization vs selective disclosure** — how protocols encode the law

## Phase 6 — Build it yourself

Reading alone doesn't stick. You have to write the code.

- [ ] **Toy Issuer** — a minimal server that issues SD-JWT VCs
- [ ] **Toy Wallet** — a CLI that receives, stores, manages keys, and signs
- [ ] **Toy Verifier** — receives a presentation, verifies signature + status
- [ ] **End-to-end** — one full Issuer → Wallet → Verifier cycle
- [ ] **Add OpenID4VCI Pre-Auth Flow** — receive a credential offer via QR
- [ ] **Add OpenID4VP cross-device flow** — browser verifier ↔ mobile wallet
- [ ] **Integrate Bitstring Status List** — make the issuer able to revoke
- [ ] **(Stretch) mdoc issuance** — ISO 18013-5 envelopes via CBOR
- [ ] **(Stretch) HAIP conformance check** — how far does your stack satisfy HAIP?

## Phase 7 — Consolidate & compare

Loop back to the start and compare.

- [ ] **Re-read the core specs** — every term should feel familiar now
- [ ] **Compare your toy stack against a production open-source stack** (`walt.id`, `Sphereon`, `sd-jwt-js`) — where does the extra complexity come from?

> **Tips:** When you get stuck, looking one layer up or down usually unblocks you. Not understanding a spec on the first read is normal — expect ~50% on the second pass, ~80% on the third. Reading real implementation code (`sd-jwt-js`, `walt.id`, `Sphereon`) *alongside* the spec roughly doubles comprehension speed.
