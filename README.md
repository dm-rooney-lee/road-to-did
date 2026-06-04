# road-to-did

Personal hands-on notes and labs for learning decentralized identity — DIDs, verifiable credentials, OpenID4VC, eIDAS.

## Roadmap

The full 7-phase learning path lives in [roadmap.md](./roadmap.md) — from crypto foundations through building a toy DID/VC stack.

## How to read

Each topic folder contains three companion files per item:

- `NN-*.notes.md` — core concepts. Read first.
- `NN-*.ts` — implementation skeleton. Exported functions with `TODO` bodies; fill them in.
- `NN-*.test.ts` — tests that verify your implementation.

## Setup

```sh
npm install
```

## Running tests

```sh
npm test
```

Tests use Node's built-in `node:test` runner via `tsx` for TypeScript support.

## Workflow per item

1. Read `NN-*.notes.md`.
2. Open `NN-*.ts`. Each exported function body throws a `TODO` until implemented.
3. Implement one function at a time, running `npm test` after each.
4. When all tests pass, answer the self-check questions at the bottom of the file.
