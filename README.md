# seekrit — Go SDK

Read-path SDK for [seekrit](https://seekrit.dev). Authenticate with a service
token, resolve your environment, and get **decrypted** secrets — the API only
ever returns ciphertext; decryption happens in your process.

> This repo is a **read-only mirror** published from seekrit's monorepo so the
> code that holds your token and decrypts plaintext is auditable. Don't commit
> here — it's overwritten on each sync. Issues and PRs welcome.

## Install

```sh
go get github.com/seekritdev/go-sdk@latest
```

Requires Go 1.24+ (uses stdlib `crypto/ecdh` and `crypto/hkdf`). **No external
dependencies.**

## Usage

```go
package main

import (
	"context"
	"fmt"
	"log"

	seekrit "github.com/seekritdev/go-sdk"
)

func main() {
	client, err := seekrit.New() // token from $SEEKRIT_TOKEN
	if err != nil {
		log.Fatal(err)
	}

	secrets, err := client.Resolve(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secrets["DATABASE_URL"])

	if v, ok, _ := client.Get(context.Background(), "API_KEY"); ok {
		fmt.Println("has API_KEY:", v != "")
	}
}
```

### Options

```go
seekrit.New(
	seekrit.WithToken("skt_…"),                        // default: $SEEKRIT_TOKEN
	seekrit.WithAPIURL("https://api.seekrit.dev"),     // default: $SEEKRIT_API_URL or hosted
	seekrit.WithOverrides(map[string]string{"shared": "dev"}), // ?with= override
	seekrit.WithHTTPClient(&http.Client{Timeout: 10 * time.Second}),
)
```

A service token binds to a single app environment (plus its composed group
slices). `WithOverrides` pulls a different environment slice of a composed
group.

### Errors

- `*seekrit.APIError` — non-2xx from the API; has `.Status` and `.Code`
  (`"unauthorized"`, `"forbidden"`, `"not_found"`, …).
- `*seekrit.CryptoError` — a token or ciphertext could not be parsed/decrypted.

`Resolve` is **fail-closed**: any resolve or decrypt failure returns an error
rather than partial results.

## Secret references

A secret's value may reference another with `${OTHER_SECRET}`. References are
stored literally and expanded here, after the layers are merged — so a reference
picks up whichever layer won that name, and rotating the referenced secret
updates every value that uses it. `$${OTHER_SECRET}` is a literal; an unknown
name is left as written; a reference cycle raises. Full rules:
[seekrit.dev/docs/guides/references](https://seekrit.dev/docs/guides/references).

```go
client, err := seekrit.New(seekrit.WithInterpolate(false)) // stored text instead
```

## Zero-knowledge

`GET /v1/resolve` returns ciphertext plus a data-encryption key wrapped to your
token's public key. This SDK recovers the token's private key, unwraps the DEK
(ECDH P-256 → HKDF-SHA256 → AES-256-GCM), and decrypts each secret
(AES-256-GCM, AAD-bound to `environmentId/NAME`) — the exact scheme used by the
CLI, `seekrit run`, and every other seekrit client. See
[seekrit.dev/docs](https://seekrit.dev/docs/concepts/encryption).

## License

MIT

## Service token v2

Keep one `SEEKRIT_TOKEN`: `skt_<id>_v2.<auth-secret>.<private-key>`.
The client sends only `skt_<id>_v2.<auth-secret>` to the API and uses the private
key locally to decrypt. Legacy tokens are rejected before any API request;
upgrade clients and replace legacy tokens through the dashboard. A stolen
HTTP credential cannot decrypt environment payloads, but stealing the full
local bundle still exposes the private key. Treat the full bundle as a secret.
