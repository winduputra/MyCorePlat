package tooldist

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const validManifest = `{
  "id": "pdf-compressor",
  "name": "PDF Compressor",
  "version": "1.0.0",
  "description": "Compress PDF files",
  "category": "Document",
  "access": "public",
  "runtime": "python",
  "upstream": "http://pdf-compressor:8000",
  "healthcheck": "/health"
}`

type entry struct {
	name string
	body string
}

// buildPackage creates a ZIP in memory. Entries are written in order so tests
// can control exactly what validation sees.
func buildPackage(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		f, err := w.Create(e.name)
		if err != nil {
			t.Fatalf("create entry %q: %v", e.name, err)
		}
		if _, err := f.Write([]byte(e.body)); err != nil {
			t.Fatalf("write entry %q: %v", e.name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func validPackage(t *testing.T) []byte {
	t.Helper()
	return buildPackage(t,
		entry{name: ManifestName, body: validManifest},
		entry{name: DockerfileName, body: "FROM scratch\n"},
		entry{name: "app/main.py", body: "print('hi')\n"},
	)
}

func TestInspectAcceptsValidPackage(t *testing.T) {
	insp, err := Inspect(validPackage(t))
	if err != nil {
		t.Fatalf("expected valid package, got error: %v", err)
	}
	if insp.Manifest.ID != "pdf-compressor" {
		t.Fatalf("manifest id = %q, want pdf-compressor", insp.Manifest.ID)
	}
	if insp.Manifest.Runtime != "python" {
		t.Fatalf("runtime = %q, want python", insp.Manifest.Runtime)
	}
	if len(insp.Files) != 3 {
		t.Fatalf("files = %d, want 3", len(insp.Files))
	}
	if len(insp.PackageSHA256) != 64 {
		t.Fatalf("package hash = %q, want 64 hex chars", insp.PackageSHA256)
	}
	if insp.TotalBytes == 0 {
		t.Fatal("total bytes must be recorded")
	}
}

func TestInspectRejectsEmptyUpload(t *testing.T) {
	if _, err := Inspect(nil); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("error = %v, want ErrInvalidPackage", err)
	}
}

func TestInspectRejectsNonZip(t *testing.T) {
	if _, err := Inspect([]byte("this is not a zip file")); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("error = %v, want ErrInvalidPackage", err)
	}
}

func TestInspectRejectsMissingManifest(t *testing.T) {
	pkg := buildPackage(t, entry{name: DockerfileName, body: "FROM scratch\n"})
	if _, err := Inspect(pkg); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("error = %v, want ErrInvalidPackage", err)
	}
}

func TestInspectRejectsMissingDockerfile(t *testing.T) {
	pkg := buildPackage(t, entry{name: ManifestName, body: validManifest})
	if _, err := Inspect(pkg); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("error = %v, want ErrInvalidPackage", err)
	}
}

func TestInspectRejectsZipSlipEntries(t *testing.T) {
	cases := []string{
		"../evil.txt",
		"a/../../evil.txt",
		"/absolute.txt",
		"\\windows\\evil.txt",
		"C:/windows/evil.txt",
		"./dotted.txt",
		"a//double.txt",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			pkg := buildPackage(t,
				entry{name: ManifestName, body: validManifest},
				entry{name: DockerfileName, body: "FROM scratch\n"},
				entry{name: name, body: "payload"},
			)
			_, err := Inspect(pkg)
			if !errors.Is(err, ErrInvalidPackage) {
				t.Fatalf("entry %q: error = %v, want ErrInvalidPackage", name, err)
			}
		})
	}
}

func TestInspectRejectsTooManyEntries(t *testing.T) {
	entries := []entry{
		{name: ManifestName, body: validManifest},
		{name: DockerfileName, body: "FROM scratch\n"},
	}
	for i := 0; i < MaxEntries; i++ {
		entries = append(entries, entry{name: "files/f" + itoa(i) + ".txt", body: "x"})
	}
	if _, err := Inspect(buildPackage(t, entries...)); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("error = %v, want ErrInvalidPackage", err)
	}
}

func TestInspectRejectsOverlongPath(t *testing.T) {
	long := strings.Repeat("a", MaxPathLength+1)
	pkg := buildPackage(t,
		entry{name: ManifestName, body: validManifest},
		entry{name: DockerfileName, body: "FROM scratch\n"},
		entry{name: long, body: "x"},
	)
	if _, err := Inspect(pkg); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("error = %v, want ErrInvalidPackage", err)
	}
}

func TestInspectRejectsInvalidManifestVariants(t *testing.T) {
	cases := map[string]string{
		"empty":       "",
		"not_json":    "{not json",
		"unknown_key": `{"id":"x","name":"X","version":"1.0.0","description":"d","access":"public","runtime":"python","upstream":"http://x:8000","healthcheck":"/h","status":"active"}`,
		"bad_id":      `{"id":"Bad_ID","name":"X","version":"1.0.0","description":"d","access":"public","runtime":"python","upstream":"http://x:8000","healthcheck":"/h"}`,
		"no_name":     `{"id":"x","name":"","version":"1.0.0","description":"d","access":"public","runtime":"python","upstream":"http://x:8000","healthcheck":"/h"}`,
		"bad_version": `{"id":"x","name":"X","version":"1.0","description":"d","access":"public","runtime":"python","upstream":"http://x:8000","healthcheck":"/h"}`,
		"no_desc":     `{"id":"x","name":"X","version":"1.0.0","description":"","access":"public","runtime":"python","upstream":"http://x:8000","healthcheck":"/h"}`,
		"bad_access":  `{"id":"x","name":"X","version":"1.0.0","description":"d","access":"private","runtime":"python","upstream":"http://x:8000","healthcheck":"/h"}`,
		"bad_runtime": `{"id":"x","name":"X","version":"1.0.0","description":"d","access":"public","runtime":"ruby","upstream":"http://x:8000","healthcheck":"/h"}`,
		"no_upstream": `{"id":"x","name":"X","version":"1.0.0","description":"d","access":"public","runtime":"python","upstream":"","healthcheck":"/h"}`,
		"bad_health":  `{"id":"x","name":"X","version":"1.0.0","description":"d","access":"public","runtime":"python","upstream":"http://x:8000","healthcheck":"health"}`,
	}
	for name, manifest := range cases {
		t.Run(name, func(t *testing.T) {
			pkg := buildPackage(t,
				entry{name: ManifestName, body: manifest},
				entry{name: DockerfileName, body: "FROM scratch\n"},
			)
			_, err := Inspect(pkg)
			if !errors.Is(err, ErrInvalidPackage) {
				t.Fatalf("error = %v, want ErrInvalidPackage", err)
			}
		})
	}
}

func TestExtractWritesFilesInsideDestination(t *testing.T) {
	dest := t.TempDir()
	if err := Extract(validPackage(t), dest); err != nil {
		t.Fatalf("extract: %v", err)
	}

	for _, name := range []string{ManifestName, DockerfileName, filepath.Join("app", "main.py")} {
		full := filepath.Join(dest, name)
		if _, err := os.Stat(full); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(dest, ManifestName))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !strings.Contains(string(data), "pdf-compressor") {
		t.Fatalf("manifest content not preserved: %s", data)
	}
}

func TestExtractRejectsZipSlip(t *testing.T) {
	pkg := buildPackage(t,
		entry{name: ManifestName, body: validManifest},
		entry{name: DockerfileName, body: "FROM scratch\n"},
		entry{name: "../escape.txt", body: "payload"},
	)
	dest := t.TempDir()
	if err := Extract(pkg, dest); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("error = %v, want ErrInvalidPackage", err)
	}
	// Nothing may be written outside dest (sibling of dest).
	sibling := filepath.Join(filepath.Dir(dest), "escape.txt")
	if _, err := os.Stat(sibling); err == nil {
		t.Fatalf("zip-slip wrote %s outside the destination", sibling)
	}
}

func TestExtractDoesNotSetExecutableBit(t *testing.T) {
	dest := t.TempDir()
	if err := Extract(validPackage(t), dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	info, err := os.Stat(filepath.Join(dest, "app", "main.py"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Windows does not model Unix permission bits for group/other, so the exact
	// 0644 assertion only holds on Unix. The security-relevant invariant on every
	// platform is that no executable bit was copied from the archive.
	if info.Mode().Perm()&0o111 != 0 {
		t.Fatalf("mode = %v, want no executable bits", info.Mode().Perm())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", info.Mode().Perm())
	}
}

// itoa avoids pulling strconv into the test for a single call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
