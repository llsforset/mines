package litebeacon

import "crypto/rand"

// randomBytes returns cryptographically secure random bytes.
func randomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err) // entropy failure is unrecoverable
	}
	return buf
}
