package litebeacon

// SecretEntry pairs a build-time shared secret with its JSON envelope key name.
type SecretEntry struct {
	SecretB64 string `json:"secret"` // base64(32 bytes)
	KeyName   string `json:"key"`
}

// jsonKeyPool is the cosmetic envelope field name pool (build-time choice).
var jsonKeyPool = []string{"data", "token", "payload", "blob", "value"}
