package installer

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// randomSecret returns 32 cryptographically random bytes.
func randomSecret() ([]byte, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("random secret: %w", err)
	}
	return buf, nil
}

// encodeBase64Std encodes using standard base64, matching Core's key file
// format (pkg/toolauth uses base64.StdEncoding).
func encodeBase64Std(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// jsonMarshalIndent marshals with indentation for a human-readable key file.
func jsonMarshalIndent(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// nowMillis is a helper for record timestamps.
func nowMillis(t time.Time) int64 { return t.UnixMilli() }
