package seekrit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestTokenWireBoundary(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Token                 string
		TokenID               string
		AuthToken             string
		Resolve               json.RawMessage
		ExpectedManagedValues map[string]string
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("authorization"); got != "Bearer "+v.AuthToken {
			t.Errorf("unexpected auth credential")
		}
		if strings.Contains(r.Header.Get("authorization"), strings.Split(v.Token, ".")[2]) {
			t.Error("private key sent")
		}
		w.Header().Set("content-type", "application/json")
		w.Write(v.Resolve)
	}))
	defer server.Close()
	c, err := New(WithToken(v.Token), WithAPIURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := c.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range v.ExpectedManagedValues {
		if secrets[name] != value {
			t.Errorf("wrong plaintext for %s", name)
		}
	}
	if _, err := parseTokenKey(v.AuthToken); err == nil {
		t.Error("auth credential accepted as decryption key")
	}
	legacy := v.TokenID + "_" + strings.Split(v.Token, ".")[2]
	if _, err := parseTokenKey(legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := New(WithToken(legacy), WithAPIURL(server.URL)); err == nil {
		t.Error("legacy credential accepted for network")
	}
	if calls != 1 {
		t.Errorf("unexpected network requests: %d", calls)
	}
}
