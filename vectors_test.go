package seekrit

// Cross-implementation parity: decrypt the shared golden vectors and assert we
// recover exactly what the canonical @seekrit/crypto (WebCrypto) produced.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type vectorFile struct {
	Token         string            `json:"token"`
	Resolve       resolveResponse   `json:"resolve"`
	Expected      map[string]string `json:"expectedManagedValues"`
	Interpolation struct {
		Cases []struct {
			Name       string            `json:"name"`
			Input      map[string]string `json:"input"`
			Expected   map[string]string `json:"expected"`
			Unresolved []string          `json:"unresolved"`
		} `json:"cases"`
		Cycles []struct {
			Name  string            `json:"name"`
			Input map[string]string `json:"input"`
		} `json:"cycles"`
	} `json:"interpolation"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func TestMaterializeMatchesExpected(t *testing.T) {
	v := loadVectors(t)
	key, err := parseTokenKey(v.Token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	merged, err := materialize(&v.Resolve, key, true)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if !reflect.DeepEqual(merged, v.Expected) {
		t.Fatalf("merged mismatch:\n got %#v\nwant %#v", merged, v.Expected)
	}
}

func TestAppLayerWinsOverGroup(t *testing.T) {
	v := loadVectors(t)
	key, _ := parseTokenKey(v.Token)
	merged, err := materialize(&v.Resolve, key, true)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if merged["SHARED"] != "from-app" {
		t.Fatalf("SHARED = %q, want app layer to win (from-app)", merged["SHARED"])
	}
}

func TestUnicodeAndEmptyRoundTrip(t *testing.T) {
	v := loadVectors(t)
	key, _ := parseTokenKey(v.Token)
	merged, _ := materialize(&v.Resolve, key, true)
	if got := merged["UNICODE"]; got != "héllo-🌍-\n-tab\tend" {
		t.Fatalf("UNICODE = %q", got)
	}
	if got, ok := merged["EMPTY"]; !ok || got != "" {
		t.Fatalf("EMPTY = %q (present=%v), want empty string present", got, ok)
	}
}

func TestReferencesExpandOverTheMergedSet(t *testing.T) {
	v := loadVectors(t)
	key, _ := parseTokenKey(v.Token)
	merged, err := materialize(&v.Resolve, key, true)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if got, want := merged["REFERENCING"], "url=postgres://group/db;shared=from-app"; got != want {
		t.Fatalf("REFERENCING = %q, want %q", got, want)
	}
	if got, want := merged["ESCAPED_REF"], "${SHARED}"; got != want {
		t.Fatalf("ESCAPED_REF = %q, want %q", got, want)
	}
	if got, want := merged["DANGLING_REF"], "build-${NOT_A_SECRET}"; got != want {
		t.Fatalf("DANGLING_REF = %q, want %q", got, want)
	}
}

func TestInterpolateOffReturnsStoredText(t *testing.T) {
	v := loadVectors(t)
	key, _ := parseTokenKey(v.Token)
	merged, err := materialize(&v.Resolve, key, false)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if got, want := merged["REFERENCING"], "url=${DATABASE_URL};shared=${SHARED}"; got != want {
		t.Fatalf("REFERENCING = %q, want %q", got, want)
	}
}

func TestSharedInterpolationVectors(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Interpolation.Cases {
		out, err := InterpolateSecrets(c.Input)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", c.Name, err)
		}
		if !reflect.DeepEqual(out.Values, c.Expected) {
			t.Fatalf("%s: values mismatch:\n got %#v\nwant %#v", c.Name, out.Values, c.Expected)
		}
		unresolved := out.Unresolved
		if unresolved == nil {
			unresolved = []string{}
		}
		want := c.Unresolved
		if want == nil {
			want = []string{}
		}
		if !reflect.DeepEqual(unresolved, want) {
			t.Fatalf("%s: unresolved = %#v, want %#v", c.Name, unresolved, want)
		}
	}
	for _, c := range v.Interpolation.Cycles {
		if _, err := InterpolateSecrets(c.Input); err == nil {
			t.Fatalf("%s: expected a cycle error", c.Name)
		}
	}
}

func TestWrongTokenCannotUnwrap(t *testing.T) {
	v := loadVectors(t)
	// A valid, well-formed token holding the wrong key must not silently succeed.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	wrong := "skt_AAAAAAAAAAAAAAAAAAAAAA_" + base64.RawURLEncoding.EncodeToString(der)
	key, err := parseTokenKey(wrong)
	if err != nil {
		t.Fatalf("parse valid-but-wrong token: %v", err)
	}
	if _, err := materialize(&v.Resolve, key, true); err == nil {
		t.Fatal("expected decrypt failure with wrong key, got success")
	}
}
