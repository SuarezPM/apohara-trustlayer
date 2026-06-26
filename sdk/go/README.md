# trustlayer (Go SDK)

> Pure Go SDK for offline verification of TrustLayer evidence bundles.
> 1:1 surface with the [`tl-wasm`](../../crates/tl-wasm/) Rust crate
> and the [`@apohara/trustlayer`](../typescript/) TypeScript SDK.

## What it does

| Function                            | Purpose                                          |
|-------------------------------------|--------------------------------------------------|
| `VerifyBundleHash(json)`            | Recompute BLAKE3 of canonical bundle JSON       |
| `ComputeCanonicalHash(json)`        | Key-order-independent hash (BLAKE3)             |
| `ValidateOrgId(id)`                 | DNS-safe check (Architect IC-4)                  |
| `ParseScittReceipt(json)`           | Extract fields from SCITT envelope               |
| `DetectWatermark(tokens, cfg)`      | Kirchenbauer z-test (token IDs)                 |

All five are 1:1 with the Rust and TypeScript SDKs. No network
round-trip; no subprocess; no CGO.

## Install

```bash
go get github.com/suarezpm/apohara-trustlayer/sdk/go
```

Requires Go 1.21+. The only external dependency is
`github.com/zeebo/blake3` (pure Go, no CGO).

## Quick start

```go
package main

import (
    "fmt"

    "github.com/suarezpm/apohara-trustlayer/sdk/go"
)

func main() {
    id, err := trustlayer.ValidateOrgId("acme")
    if err != nil {
        panic(err)
    }
    fmt.Println("validated:", id)

    h, _ := trustlayer.ComputeCanonicalHash(`{"b":2,"a":1}`)
    fmt.Println("hash:", h)
}
```

## Build / test

```bash
go test ./...        # 16 tests pass
go test -v ./...     # verbose
```

## License

MIT OR Apache-2.0
