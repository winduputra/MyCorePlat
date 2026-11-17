package service

import (
	"errors"
	"testing"
)

const validManifest = `{
  "id": "image-compressor",
  "name": "Image Compressor",
  "version": "1.0.0",
  "description": "Compress JPG, PNG, and WebP images",
  "category": "Image",
  "access": "public",
  "runtime": "python",
  "upstream": "http://image-compressor:8000",
  "healthcheck": "/health"
}`

func TestParseManifestValid(t *testing.T) {
	m, err := ParseManifest([]byte(validManifest), testAllowlist())
	if err != nil {
		t.Fatalf("ParseManifest error: %v", err)
	}
	if m.ID != "image-compressor" {
		t.Errorf("ID = %q", m.ID)
	}
	if m.Name != "Image Compressor" {
		t.Errorf("Name = %q", m.Name)
	}
	if m.Version != "1.0.0" {
		t.Errorf("Version = %q", m.Version)
	}
	if m.Access != "public" {
		t.Errorf("Access = %q", m.Access)
	}
	if m.Runtime != "python" {
		t.Errorf("Runtime = %q", m.Runtime)
	}
	if m.Upstream != "http://image-compressor:8000" {
		t.Errorf("Upstream = %q", m.Upstream)
	}
	if m.Healthcheck != "/health" {
		t.Errorf("Healthcheck = %q", m.Healthcheck)
	}
}

func TestParseManifestRejectsMalformedJSON(t *testing.T) {
	if _, err := ParseManifest([]byte(`{not json`), testAllowlist()); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("error = %v, want ErrInvalidManifest", err)
	}
}

func TestParseManifestRejectsUnknownField(t *testing.T) {
	bad := `{
	  "id": "x", "name": "X", "version": "1.0.0", "description": "d",
	  "access": "public", "runtime": "go", "upstream": "http://x:8000",
	  "healthcheck": "/health",
	  "status": "active"
	}`
	if _, err := ParseManifest([]byte(bad), testAllowlist()); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("error = %v, want ErrInvalidManifest (unknown field must be rejected)", err)
	}
}

func TestParseManifestRequiresMandatoryFields(t *testing.T) {
	cases := map[string]string{
		"missing id":          `{"name":"N","version":"1.0.0","description":"d","access":"public","runtime":"go","upstream":"http://x:8000","healthcheck":"/health"}`,
		"missing name":        `{"id":"x","version":"1.0.0","description":"d","access":"public","runtime":"go","upstream":"http://x:8000","healthcheck":"/health"}`,
		"missing version":     `{"id":"x","name":"N","description":"d","access":"public","runtime":"go","upstream":"http://x:8000","healthcheck":"/health"}`,
		"missing description": `{"id":"x","name":"N","version":"1.0.0","access":"public","runtime":"go","upstream":"http://x:8000","healthcheck":"/health"}`,
		"missing access":      `{"id":"x","name":"N","version":"1.0.0","description":"d","runtime":"go","upstream":"http://x:8000","healthcheck":"/health"}`,
		"missing runtime":     `{"id":"x","name":"N","version":"1.0.0","description":"d","access":"public","upstream":"http://x:8000","healthcheck":"/health"}`,
		"missing upstream":    `{"id":"x","name":"N","version":"1.0.0","description":"d","access":"public","runtime":"go","healthcheck":"/health"}`,
		"missing healthcheck": `{"id":"x","name":"N","version":"1.0.0","description":"d","access":"public","runtime":"go","upstream":"http://x:8000"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseManifest([]byte(body), testAllowlist()); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("error = %v, want ErrInvalidManifest", err)
			}
		})
	}
}

func TestParseManifestValidatesFieldFormats(t *testing.T) {
	cases := map[string]string{
		"bad id uppercase":   `{"id":"Bad","name":"N","version":"1.0.0","description":"d","access":"public","runtime":"go","upstream":"http://x:8000","healthcheck":"/health"}`,
		"bad id double dash": `{"id":"a--b","name":"N","version":"1.0.0","description":"d","access":"public","runtime":"go","upstream":"http://x:8000","healthcheck":"/health"}`,
		"bad version":        `{"id":"x","name":"N","version":"1.0","description":"d","access":"public","runtime":"go","upstream":"http://x:8000","healthcheck":"/health"}`,
		"bad access enum":    `{"id":"x","name":"N","version":"1.0.0","description":"d","access":"secret","runtime":"go","upstream":"http://x:8000","healthcheck":"/health"}`,
		"bad runtime enum":   `{"id":"x","name":"N","version":"1.0.0","description":"d","access":"public","runtime":"ruby","upstream":"http://x:8000","healthcheck":"/health"}`,
		"bad healthcheck":    `{"id":"x","name":"N","version":"1.0.0","description":"d","access":"public","runtime":"go","upstream":"http://x:8000","healthcheck":"health"}`,
		"empty name":         `{"id":"x","name":"","version":"1.0.0","description":"d","access":"public","runtime":"go","upstream":"http://x:8000","healthcheck":"/health"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseManifest([]byte(body), testAllowlist()); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("error = %v, want ErrInvalidManifest", err)
			}
		})
	}
}

func TestParseManifestRejectsPublicUpstream(t *testing.T) {
	bad := `{"id":"x","name":"N","version":"1.0.0","description":"d","access":"public","runtime":"go","upstream":"https://example.com:443/x","healthcheck":"/health"}`
	if _, err := ParseManifest([]byte(bad), testAllowlist()); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("error = %v, want ErrInvalidManifest for public upstream", err)
	}
}

// TestParseManifestCannotSetStatusOrSecurity asserts the manifest schema has no
// status/access-control fields that could override DB-managed values.
func TestParseManifestCannotSetStatusOrSecurity(t *testing.T) {
	// "status" and "enabled" are not part of the manifest schema; supplying them
	// must be rejected as unknown fields rather than silently applied.
	for _, body := range []string{
		`{"id":"x","name":"N","version":"1.0.0","description":"d","access":"public","runtime":"go","upstream":"http://x:8000","healthcheck":"/health","status":"active"}`,
		`{"id":"x","name":"N","version":"1.0.0","description":"d","access":"public","runtime":"go","upstream":"http://x:8000","healthcheck":"/health","enabled":true}`,
	} {
		if _, err := ParseManifest([]byte(body), testAllowlist()); !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("error = %v, want ErrInvalidManifest for manifest trying to set status/security", err)
		}
	}
}

func TestParseManifestAcceptsOptionalFields(t *testing.T) {
	body := `{
	  "id": "x", "name": "N", "version": "1.0.0", "description": "d",
	  "access": "public", "runtime": "go", "upstream": "http://x:8000",
	  "healthcheck": "/health", "displayOrder": 3, "icon": "img.png",
	  "schemaVersion": "1"
	}`
	m, err := ParseManifest([]byte(body), testAllowlist())
	if err != nil {
		t.Fatalf("ParseManifest error: %v", err)
	}
	if m.DisplayOrder != 3 {
		t.Errorf("DisplayOrder = %d, want 3", m.DisplayOrder)
	}
	if m.Icon != "img.png" {
		t.Errorf("Icon = %q", m.Icon)
	}
}
