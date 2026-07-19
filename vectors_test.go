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
	Token    string            `json:"token"`
	Resolve  resolveResponse   `json:"resolve"`
	Expected map[string]string `json:"expectedManagedValues"`
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
	merged, err := materialize(&v.Resolve, key)
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
	merged, err := materialize(&v.Resolve, key)
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
	merged, _ := materialize(&v.Resolve, key)
	if got := merged["UNICODE"]; got != "héllo-🌍-\n-tab\tend" {
		t.Fatalf("UNICODE = %q", got)
	}
	if got, ok := merged["EMPTY"]; !ok || got != "" {
		t.Fatalf("EMPTY = %q (present=%v), want empty string present", got, ok)
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
	if _, err := materialize(&v.Resolve, key); err == nil {
		t.Fatal("expected decrypt failure with wrong key, got success")
	}
}
