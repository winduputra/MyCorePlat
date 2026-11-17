package tooldist

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MaxFileBytes caps a single extracted file. Kept well below the package cap so
// one entry cannot dominate a build context.
const MaxFileBytes int64 = 64 << 20 // 64 MiB

// Extract writes a previously inspected package into destDir.
//
// The paths were already validated by Inspect, but they are re-checked here so
// that extraction is safe even if a future caller reaches this function without
// running Inspect. Every resolved path must stay inside destDir.
func Extract(packageBytes []byte, destDir string) error {
	reader, err := zip.NewReader(bytes.NewReader(packageBytes), int64(len(packageBytes)))
	if err != nil {
		return fmt.Errorf("%w: not a readable zip archive", ErrInvalidPackage)
	}

	cleanDest := filepath.Clean(destDir)
	if err := os.MkdirAll(cleanDest, 0o755); err != nil {
		return fmt.Errorf("create package directory: %w", err)
	}

	for _, f := range reader.File {
		if err := validateEntryPath(f.Name); err != nil {
			return err
		}

		target := filepath.Join(cleanDest, filepath.FromSlash(strings.TrimSuffix(f.Name, "/")))

		// Final containment check: the joined path must remain under destDir.
		rel, err := filepath.Rel(cleanDest, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("%w: entry escapes package directory", ErrInvalidPackage)
		}

		if strings.HasSuffix(f.Name, "/") {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("create directory: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("create parent directory: %w", err)
		}

		if err := extractFile(f, target); err != nil {
			return err
		}
	}
	return nil
}

func extractFile(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open entry: %w", err)
	}
	defer rc.Close()

	// 0644 for files; never copy an executable bit from an untrusted archive.
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer out.Close()

	// OpenFile applies the umask (and on Windows the default is permissive), so
	// enforce the mode explicitly: package files are data, never writable by
	// group/other and never executable.
	if err := out.Chmod(0o644); err != nil {
		return fmt.Errorf("set file mode: %w", err)
	}

	if _, err := io.Copy(out, io.LimitReader(rc, MaxFileBytes+1)); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}
