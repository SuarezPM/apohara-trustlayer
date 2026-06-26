# @apohara/trustlayer

> WASM-based TypeScript SDK for offline verification of TrustLayer evidence bundles.
> Reuses the [`tl-wasm`](../../crates/tl-wasm/) Rust crate.

[![npm](https://img.shields.io/npm/v/@apohara/trustlayer.svg)](https://www.npmjs.com)

## What it does

Five pure-logic operations for the browser / edge / Node.js:

| Method                                  | Purpose                                          |
|-----------------------------------------|--------------------------------------------------|
| `verifyBundleHash(json)`                | Recompute BLAKE3 of canonical bundle JSON       |
| `computeCanonicalHash(json)`            | Key-order-independent hash (BLAKE3)             |
| `validateOrgId(id)`                     | DNS-safe check (Architect IC-4)                  |
| `parseScittReceipt(json)`               | Extract fields from SCITT envelope               |
| `detectWatermark(text)`                 | Byte-level Kirchenbauer z-test                   |

All five are 1:1 with the Rust crate's `#[wasm_bindgen]` exports. No
network round-trip; no subprocess; no cryptographic keys in userland.

## Install

```bash
npm install @apohara/trustlayer
```

## Quick start

```ts
import { TrustLayerWasm } from "@apohara/trustlayer";

// Node 20+ builds load WASM synchronously at import time.
const ok = TrustLayerWasm.verifyBundleHash(bundleJson);
const id = TrustLayerWasm.validateOrgId("acme");
const wm = TrustLayerWasm.detectWatermark("Hello, world!");

if (ok) console.log("bundle verified:", id);
```

For browser / edge builds (Cloudflare Workers, Deno, Bun):

```ts
import { TrustLayerWasm } from "@apohara/trustlayer";

await TrustLayerWasm.init();   // async load .wasm
const ok = TrustLayerWasm.verifyBundleHash(bundleJson);
```

## Bundle size

`tl_wasm_bg.wasm` is **~108 KB un-gzipped** (target: <100 KB gzipped
per Plan v1.1 v1.1.0-US-11). No native dependencies.

## Build

```bash
npm install
npm run build      # wasm-pack + tsup + copy
npm test           # vitest
npm run typecheck  # tsc --noEmit
```

`dist/` ends up with:

```
dist/
  index.cjs     4.2 KB
  index.js      2.4 KB
  index.d.ts    4.3 KB
  index.d.cts   4.3 KB
  tl_wasm_bg.wasm   108 KB
```

## License

MIT OR Apache-2.0
