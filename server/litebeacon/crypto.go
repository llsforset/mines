package litebeacon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand" // randomBytes (written in Task 1) lives in this file
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

const (
	keyCtx       = "lite/aead/v1" // must match AEAD_CTX in implant/lite/main.c
	nonceSize    = 12
	maxClockSkew = 300 * time.Second
)

// deriveKey folds a shared secret into the AEAD key domain.
func deriveKey(secret []byte) [32]byte {
	var key [32]byte
	h := sha256.New()
	h.Write(secret)
	h.Write([]byte(keyCtx))
	copy(key[:], h.Sum(nil))
	return key
}

// sealBody encrypts plaintext and wraps it in a single-field JSON envelope:
// {"<keyName>":"<base64(nonce||ciphertext||tag)>"}
func sealBody(keyName string, key [32]byte, plaintext []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(nonceSize)
	sealed := aead.Seal(nonce, nonce, plaintext, nil)
	return json.Marshal(map[string]string{keyName: base64.StdEncoding.EncodeToString(sealed)})
}

// openBody decodes the envelope and tries every registered secret. The matched
// entry is returned so the caller can respond with the same key name.
func openBody(body []byte, entries []SecretEntry) (plain []byte, matched SecretEntry, nonce []byte, err error) {
	var env map[string]string
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, matched, nil, err
	}
	if len(env) != 1 {
		return nil, matched, nil, errors.New("envelope must have exactly one field")
	}
	var encoded string
	for _, v := range env {
		encoded = v
	}
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, matched, nil, err
	}
	if len(sealed) < nonceSize+16 {
		return nil, matched, nil, errors.New("ciphertext too short")
	}
	nonce = sealed[:nonceSize]
	for _, entry := range entries {
		secret, decErr := base64.StdEncoding.DecodeString(entry.SecretB64)
		if decErr != nil || len(secret) != 32 {
			continue
		}
		aead, aErr := newGCM(deriveKey(secret))
		if aErr != nil {
			continue
		}
		if pt, openErr := aead.Open(nil, nonce, sealed[nonceSize:], nil); openErr == nil {
			return pt, entry, nonce, nil
		}
	}
	return nil, matched, nil, errors.New("no secret matched")
}

func newGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// randomBytes returns cryptographically secure random bytes.
func randomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err) // entropy failure is unrecoverable
	}
	return buf
}
