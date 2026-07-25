// Zero-knowledge read path, byte-compatible with @seekrit/crypto and
// crates/seekrit-core. Three steps:
//
//  1. Recover the service token's P-256 private key  (parseTokenKey).
//  2. Unwrap each environment DEK                     (tokenKey.unwrapDEK).
//  3. Decrypt each secret                             (decryptSecret).
//
// Blob formats (all segments base64url, no padding):
//
//	token       skt_<id>_<pkcs8 private key>
//	wrapped DEK wd1.<ephemeral pub (raw SEC1)>.<hkdf salt>.<iv>.<ciphertext||tag>
//	secret      sc1.<iv>.<ciphertext||tag>
package seekrit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"regexp"
	"strings"
)

const hkdfInfo = "seekrit/wrap-dek/v1"

// Only the first two underscores are separators; the key segment may contain "_".
var tokenRE = regexp.MustCompile(`^(skt_[0-9A-Za-z]+)_([A-Za-z0-9_-]+)$`)

var b64 = base64.RawURLEncoding

func splitBlob(blob, prefix string, segments int) ([]string, error) {
	parts := strings.Split(blob, ".")
	if len(parts) == 0 || parts[0] != prefix {
		return nil, &CryptoError{msg: "expected a \"" + prefix + "\" blob"}
	}
	if len(parts) != segments+1 {
		return nil, &CryptoError{msg: "malformed \"" + prefix + "\" blob"}
	}
	for _, p := range parts {
		if p == "" {
			return nil, &CryptoError{msg: "malformed \"" + prefix + "\" blob"}
		}
	}
	return parts[1:], nil
}

// secretAAD binds a secret ciphertext to its environment and name.
func secretAAD(environmentID, name string) []byte {
	return []byte(environmentID + "/" + name)
}

// tokenKey is the P-256 private key recovered from a skt_... service token.
type tokenKey struct {
	tokenID string
	priv    *ecdh.PrivateKey
}

func parseTokenKey(token string) (*tokenKey, error) {
	m := tokenRE.FindStringSubmatch(token)
	if m == nil {
		return nil, &CryptoError{msg: "not a valid seekrit service token"}
	}
	der, err := b64.DecodeString(m[2])
	if err != nil {
		return nil, &CryptoError{msg: "service token private key is corrupted", cause: err}
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, &CryptoError{msg: "service token private key is corrupted", cause: err}
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, &CryptoError{msg: "service token key is not an EC private key"}
	}
	priv, err := ecKey.ECDH()
	if err != nil {
		return nil, &CryptoError{msg: "service token key is not on the P-256 curve", cause: err}
	}
	return &tokenKey{tokenID: m[1], priv: priv}, nil
}

// unwrapDEK recovers a 32-byte environment DEK from a wd1. blob.
func (k *tokenKey) unwrapDEK(wrapped string) ([]byte, error) {
	seg, err := splitBlob(wrapped, "wd1", 4)
	if err != nil {
		return nil, err
	}
	ephRaw, err1 := b64.DecodeString(seg[0])
	salt, err2 := b64.DecodeString(seg[1])
	iv, err3 := b64.DecodeString(seg[2])
	ct, err4 := b64.DecodeString(seg[3])
	if err := firstErr(err1, err2, err3, err4); err != nil {
		return nil, &CryptoError{msg: "malformed \"wd1\" blob", cause: err}
	}
	ephPub, err := ecdh.P256().NewPublicKey(ephRaw)
	if err != nil {
		return nil, &CryptoError{msg: "DEK unwrap failed: bad ephemeral key", cause: err}
	}
	shared, err := k.priv.ECDH(ephPub)
	if err != nil {
		return nil, &CryptoError{msg: "DEK unwrap failed: ECDH error", cause: err}
	}
	wrappingKey, err := hkdf.Key(sha256.New, shared, salt, hkdfInfo, 32)
	if err != nil {
		return nil, &CryptoError{msg: "DEK unwrap failed: HKDF error", cause: err}
	}
	dek, err := aesGCMOpen(wrappingKey, iv, ct, nil)
	if err != nil {
		return nil, &CryptoError{msg: "DEK unwrap failed: wrong private key or tampered grant", cause: err}
	}
	if len(dek) != 32 {
		return nil, &CryptoError{msg: "unwrapped DEK has wrong length"}
	}
	return dek, nil
}

// decryptSecret decrypts an sc1. secret ciphertext to its UTF-8 plaintext.
func decryptSecret(dek []byte, blob string, aad []byte) (string, error) {
	seg, err := splitBlob(blob, "sc1", 2)
	if err != nil {
		return "", err
	}
	iv, err1 := b64.DecodeString(seg[0])
	ct, err2 := b64.DecodeString(seg[1])
	if err := firstErr(err1, err2); err != nil {
		return "", &CryptoError{msg: "malformed \"sc1\" blob", cause: err}
	}
	plaintext, err := aesGCMOpen(dek, iv, ct, aad)
	if err != nil {
		return "", &CryptoError{msg: "secret decryption failed: wrong key, tampered data, or mismatched context", cause: err}
	}
	return string(plaintext), nil
}

func aesGCMOpen(key, iv, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, ciphertext, aad)
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// materialize decrypts every layer and merges by precedence. Layers arrive
// lowest precedence first (composed groups, then the app environment); later
// layers overwrite earlier ones on a name collision.
//
// ${OTHER_SECRET} references are then expanded over the merged result (so a
// reference sees whichever layer won the name), unless interpolate is false.
func materialize(resp *resolveResponse, key *tokenKey, interpolate bool) (map[string]string, error) {
	merged := make(map[string]string)
	for _, layer := range resp.Layers {
		dek, err := key.unwrapDEK(layer.WrappedDEK)
		if err != nil {
			return nil, err
		}
		for _, s := range layer.Secrets {
			value, err := decryptSecret(dek, s.Ciphertext, secretAAD(layer.EnvironmentID, s.Name))
			if err != nil {
				return nil, err
			}
			merged[s.Name] = value
		}
	}
	if !interpolate {
		return merged, nil
	}
	expanded, err := InterpolateSecrets(merged)
	if err != nil {
		return nil, err
	}
	return expanded.Values, nil
}
