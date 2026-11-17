package toolauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// KeyStatus is the lifecycle state of a signing key.
type KeyStatus string

const (
	// KeyStatusActive marks the key Core signs with.
	KeyStatusActive KeyStatus = "active"
	// KeyStatusPrevious marks a retired key a tool still accepts during the
	// bounded rotation window. Core never signs with it.
	KeyStatusPrevious KeyStatus = "previous"
	// KeyStatusRevoked marks a key that must be rejected even if its signature
	// verifies.
	KeyStatusRevoked KeyStatus = "revoked"
)

// minSecretBytes rejects obviously weak provisioned secrets.
const minSecretBytes = 16

// Key is a signing/verification key. The secret is never exposed by String or
// any error message.
type Key struct {
	ID       string     `json:"keyId"`
	Status   KeyStatus  `json:"status"`
	NotAfter *time.Time `json:"notAfter,omitempty"`

	secret []byte
}

// NewKey builds a key from raw secret bytes.
func NewKey(id string, secret []byte, status KeyStatus, notAfter *time.Time) (Key, error) {
	if id == "" {
		return Key{}, errors.New("toolauth: key id must not be empty")
	}
	if len(secret) < minSecretBytes {
		return Key{}, fmt.Errorf("toolauth: key %q secret must be at least %d bytes", id, minSecretBytes)
	}
	switch status {
	case KeyStatusActive, KeyStatusPrevious, KeyStatusRevoked:
	default:
		return Key{}, fmt.Errorf("toolauth: key %q has invalid status %q", id, status)
	}
	cloned := make([]byte, len(secret))
	copy(cloned, secret)
	return Key{ID: id, Status: status, NotAfter: notAfter, secret: cloned}, nil
}

// Secret returns a copy of the secret bytes for signing or verifying.
func (k Key) Secret() []byte {
	out := make([]byte, len(k.secret))
	copy(out, k.secret)
	return out
}

// String deliberately omits the secret so logging a key is safe.
func (k Key) String() string {
	return fmt.Sprintf("toolauth.Key{id:%q,status:%q}", k.ID, k.Status)
}

// Usable reports whether the key may be used at now: not revoked, and not
// past its optional NotAfter deadline.
func (k Key) Usable(now time.Time) bool {
	if k.Status == KeyStatusRevoked {
		return false
	}
	if k.NotAfter != nil && !now.Before(*k.NotAfter) {
		return false
	}
	return true
}

// KeySet is an immutable collection of keys addressed by key id.
type KeySet struct {
	keys map[string]Key
}

// NewKeySet indexes keys by id. Duplicate ids are rejected by returning an
// error so a misprovisioned file cannot silently shadow a key.
func NewKeySet(keys ...Key) (KeySet, error) {
	set := KeySet{keys: make(map[string]Key, len(keys))}
	for _, key := range keys {
		if _, exists := set.keys[key.ID]; exists {
			return KeySet{}, fmt.Errorf("toolauth: duplicate key id %q", key.ID)
		}
		set.keys[key.ID] = key
	}
	return set, nil
}

// Lookup returns the key with the given id.
func (ks KeySet) Lookup(keyID string) (Key, bool) {
	key, ok := ks.keys[keyID]
	return key, ok
}

// Len reports how many keys the set holds.
func (ks KeySet) Len() int { return len(ks.keys) }

// Active returns the key Core must sign with at now.
func (ks KeySet) Active(now time.Time) (Key, error) {
	for _, key := range ks.keys {
		if key.Status == KeyStatusActive && key.Usable(now) {
			return key, nil
		}
	}
	return Key{}, ErrNoActiveKey
}

// KeyStore resolves the key set provisioned for a tool.
type KeyStore interface {
	Keys(ctx context.Context, toolSlug string) (KeySet, error)
}

// FileKeyStore reads per-tool key sets from a directory of provisioned secret
// files: <dir>/<tool-slug>.json. Files are the provisioning channel (Docker
// secret or a 0600 file); they are never served, logged, or exported.
//
// Rotation is a file update: add the new key as "active", demote the old one to
// "previous" with a bounded notAfter, then mark it "revoked". The store reloads
// the file when its modification time or size changes, so rotation does not
// need a restart.
type FileKeyStore struct {
	dir string

	mu    sync.Mutex
	cache map[string]keyFileCacheEntry
}

type keyFileCacheEntry struct {
	modTime time.Time
	size    int64
	keys    KeySet
}

type keyFileFormat struct {
	ToolSlug string         `json:"toolSlug"`
	Keys     []keyFileEntry `json:"keys"`
}

type keyFileEntry struct {
	KeyID    string     `json:"keyId"`
	Secret   string     `json:"secret"`
	Status   KeyStatus  `json:"status"`
	NotAfter *time.Time `json:"notAfter,omitempty"`
}

var toolSlugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// NewFileKeyStore returns a store reading from dir. An empty dir yields a store
// that reports ErrKeyStoreUnavailable for every lookup (signing stays disabled).
func NewFileKeyStore(dir string) *FileKeyStore {
	return &FileKeyStore{dir: dir, cache: make(map[string]keyFileCacheEntry)}
}

// Keys implements KeyStore.
func (s *FileKeyStore) Keys(_ context.Context, toolSlug string) (KeySet, error) {
	if s == nil || s.dir == "" {
		return KeySet{}, ErrKeyStoreUnavailable
	}
	// The slug is interpolated into a file path, so it is validated strictly.
	if !toolSlugPattern.MatchString(toolSlug) {
		return KeySet{}, ErrKeyNotFound
	}
	path := filepath.Join(s.dir, toolSlug+".json")

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return KeySet{}, ErrKeyNotFound
		}
		return KeySet{}, fmt.Errorf("%w: %s", ErrKeyStoreUnavailable, path)
	}

	s.mu.Lock()
	cached, ok := s.cache[toolSlug]
	s.mu.Unlock()
	if ok && cached.modTime.Equal(info.ModTime()) && cached.size == info.Size() {
		return cached.keys, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return KeySet{}, fmt.Errorf("%w: %s", ErrKeyStoreUnavailable, path)
	}
	var parsed keyFileFormat
	if err := json.Unmarshal(raw, &parsed); err != nil {
		// Deliberately does not echo the file contents.
		return KeySet{}, fmt.Errorf("%w: %s is not valid JSON", ErrKeyStoreUnavailable, path)
	}
	keys := make([]Key, 0, len(parsed.Keys))
	for _, entry := range parsed.Keys {
		secret, err := base64.StdEncoding.DecodeString(entry.Secret)
		if err != nil {
			return KeySet{}, fmt.Errorf("%w: %s has a key with an invalid base64 secret", ErrKeyStoreUnavailable, path)
		}
		key, err := NewKey(entry.KeyID, secret, entry.Status, entry.NotAfter)
		if err != nil {
			return KeySet{}, fmt.Errorf("%w: %s", ErrKeyStoreUnavailable, path)
		}
		keys = append(keys, key)
	}
	set, err := NewKeySet(keys...)
	if err != nil {
		return KeySet{}, fmt.Errorf("%w: %s", ErrKeyStoreUnavailable, path)
	}

	s.mu.Lock()
	s.cache[toolSlug] = keyFileCacheEntry{modTime: info.ModTime(), size: info.Size(), keys: set}
	s.mu.Unlock()
	return set, nil
}
