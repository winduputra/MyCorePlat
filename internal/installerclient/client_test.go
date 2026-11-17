package installerclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New("", "token", 0); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("empty base url: got %v, want ErrNotConfigured", err)
	}
	if _, err := New("http://installer:8090", "", 0); err == nil {
		t.Fatal("empty token should be rejected")
	}
	if _, err := New("ftp://installer", "token", 0); err == nil {
		t.Fatal("non-http scheme should be rejected")
	}
}

func TestInstallSendsBearerAndReturnsInstallation(t *testing.T) {
	var gotAuth, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		gotBody = readAll(r)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(Installation{Slug: "demo-tool", Status: "installed", ToolID: 7})
	}))
	defer srv.Close()

	c, err := New(srv.URL, "secret-token", 0)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := c.Install(context.Background(), []byte("zipdata"), 3)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("auth header = %q", gotAuth)
	}
	if gotCT != "application/zip" {
		t.Errorf("content type = %q", gotCT)
	}
	if string(gotBody) != "zipdata" {
		t.Errorf("body = %q", gotBody)
	}
	if inst.Slug != "demo-tool" || inst.Status != "installed" || inst.ToolID != 7 {
		t.Errorf("decoded installation = %+v", inst)
	}
}

func TestInstallMapsTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "tok", 0)
	if _, err := c.Install(context.Background(), []byte("x"), 1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
}

func TestInstallMapsPackageRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "package_invalid", "message": "zip-slip detected"})
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "tok", 0)
	err := installErr(t, c)
	if !errors.Is(err, ErrPackage) {
		t.Fatalf("got %v, want ErrPackage", err)
	}
	if !strings.Contains(err.Error(), "zip-slip") {
		t.Errorf("message %q should carry the installer reason", err.Error())
	}
}

func TestListDecodesInstallations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"installations": []Installation{{Slug: "a"}, {Slug: "b"}},
		})
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "tok", 0)
	got, err := c.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Slug != "a" || got[1].Slug != "b" {
		t.Errorf("list = %+v", got)
	}
}

func TestGetNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "tok", 0)
	if _, err := c.Get(context.Background(), "missing-tool"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestGetRejectsInvalidSlugWithoutRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("server should not be contacted for an invalid slug")
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "tok", 0)
	if _, err := c.Get(context.Background(), "Bad_Slug"); !errors.Is(err, ErrInvalidSlug) {
		t.Fatalf("got %v, want ErrInvalidSlug", err)
	}
}

func TestLifecycleEndpoints(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "tok", 0)
	ctx := context.Background()
	if err := c.Enable(ctx, "demo-tool"); err != nil {
		t.Fatal(err)
	}
	if err := c.Disable(ctx, "demo-tool"); err != nil {
		t.Fatal(err)
	}
	if err := c.Uninstall(ctx, "demo-tool"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /v1/tools/demo-tool/enable",
		"POST /v1/tools/demo-tool/disable",
		"DELETE /v1/tools/demo-tool",
	}
	if len(paths) != 3 {
		t.Fatalf("paths = %v", paths)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("path[%d] = %q, want %q", i, paths[i], want[i])
		}
	}
}

func TestDoMapsServerErrorToUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "tok", 0)
	if _, err := c.List(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}
}

func TestConfiguredReflectsState(t *testing.T) {
	var nilClient *Client
	if nilClient.Configured() {
		t.Error("nil client should not be configured")
	}
	c, _ := New("http://installer:8090", "tok", 0)
	if !c.Configured() {
		t.Error("client with base url should be configured")
	}
}

func installErr(t *testing.T, c *Client) error {
	t.Helper()
	_, err := c.Install(context.Background(), []byte("x"), 1)
	if err == nil {
		t.Fatal("expected an error")
	}
	return err
}

func readAll(r *http.Request) []byte {
	buf := make([]byte, 0, 64)
	tmp := make([]byte, 64)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf
		}
	}
}
