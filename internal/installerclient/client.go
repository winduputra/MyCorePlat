// Package installerclient is the Core-side HTTP client for the tool installer
// service.
//
// Core deliberately never touches the Docker Engine API. Uploading a tool
// package, building an image, creating the container and provisioning the
// per-tool HMAC secret all happen inside the installer service, which is the
// only component with access to the Docker socket. Core simply forwards the
// operator's request and surfaces the result in the admin dashboard.
package installerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Errors returned by the client. Callers map these onto HTTP responses for the
// admin dashboard; the underlying installer message is safe to show because the
// installer never includes secrets or internal paths in its error text.
var (
	ErrNotConfigured = errors.New("tool installer is not configured")
	ErrInvalidSlug   = errors.New("invalid tool slug")
	ErrNotFound      = errors.New("tool installation not found")
	ErrConflict      = errors.New("tool is busy or already installed")
	ErrPackage       = errors.New("tool package was rejected")
	ErrTooLarge      = errors.New("tool package is too large")
	ErrUnavailable   = errors.New("tool installer is unavailable")
)

// Installation mirrors the installer's install record. Only the fields the
// admin dashboard renders are decoded.
type Installation struct {
	ID            uint64 `json:"id"`
	ToolID        uint64 `json:"toolId"`
	Slug          string `json:"slug"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	ImageTag      string `json:"imageTag"`
	ContainerName string `json:"containerName"`
	ErrorCode     string `json:"errorCode"`
	ErrorMessage  string `json:"errorMessage"`
	CreatedAt     int64  `json:"createdAt"`
	UpdatedAt     int64  `json:"updatedAt"`
}

// Client talks to the installer service over its bearer-token API.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// New builds a client. Both baseURL and token must be non-empty; callers are
// expected to have validated the configuration already.
func New(baseURL, token string, timeout time.Duration) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("installer token is required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse installer base url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("installer base url must use http or https")
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: timeout,
			// The installer is an internal service; never follow redirects to
			// somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Configured reports whether the client has usable settings.
func (c *Client) Configured() bool {
	return c != nil && c.baseURL != ""
}

// Install uploads a ZIP package. The raw bytes are sent as the request body so
// the installer can hash exactly what the operator uploaded.
func (c *Client) Install(ctx context.Context, packageBytes []byte, adminID uint64) (*Installation, error) {
	if !c.Configured() {
		return nil, ErrNotConfigured
	}
	endpoint := fmt.Sprintf("%s/v1/tools?admin_id=%d", c.baseURL, adminID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(packageBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.ContentLength = int64(len(packageBytes))

	status, body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusCreated, http.StatusOK:
		var inst Installation
		if err := json.Unmarshal(body, &inst); err != nil {
			return nil, fmt.Errorf("decode installer response: %w", err)
		}
		return &inst, nil
	case http.StatusRequestEntityTooLarge:
		return nil, ErrTooLarge
	default:
		return nil, c.mapError(status, body)
	}
}

// List returns every installation the installer knows about.
func (c *Client) List(ctx context.Context) ([]Installation, error) {
	if !c.Configured() {
		return nil, ErrNotConfigured
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/tools", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	status, body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, c.mapError(status, body)
	}
	var payload struct {
		Installations []Installation `json:"installations"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode installer response: %w", err)
	}
	return payload.Installations, nil
}

// Get returns one installation by slug.
func (c *Client) Get(ctx context.Context, slug string) (*Installation, error) {
	if !validSlug(slug) {
		return nil, ErrInvalidSlug
	}
	if !c.Configured() {
		return nil, ErrNotConfigured
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/tools/"+url.PathEscape(slug), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	status, body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		var inst Installation
		if err := json.Unmarshal(body, &inst); err != nil {
			return nil, fmt.Errorf("decode installer response: %w", err)
		}
		return &inst, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		return nil, c.mapError(status, body)
	}
}

// Enable activates a tool, Disable deactivates it, and Uninstall removes it.
func (c *Client) Enable(ctx context.Context, slug string) error {
	return c.lifecycle(ctx, http.MethodPost, slug, "enable")
}

func (c *Client) Disable(ctx context.Context, slug string) error {
	return c.lifecycle(ctx, http.MethodPost, slug, "disable")
}

func (c *Client) Uninstall(ctx context.Context, slug string) error {
	return c.lifecycle(ctx, http.MethodDelete, slug, "")
}

func (c *Client) lifecycle(ctx context.Context, method, slug, action string) error {
	if !validSlug(slug) {
		return ErrInvalidSlug
	}
	if !c.Configured() {
		return ErrNotConfigured
	}
	endpoint := c.baseURL + "/v1/tools/" + url.PathEscape(slug)
	if action != "" {
		endpoint += "/" + action
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	status, body, err := c.do(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case status == http.StatusNotFound:
		return ErrNotFound
	default:
		return c.mapError(status, body)
	}
}

func (c *Client) do(req *http.Request) (int, []byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	// Installer responses are small; cap the read so a misbehaving service
	// cannot exhaust Core memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("%w: read response", ErrUnavailable)
	}
	return resp.StatusCode, body, nil
}

func (c *Client) mapError(status int, body []byte) error {
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &payload)

	switch status {
	case http.StatusBadRequest:
		return fmt.Errorf("%w: %s", ErrPackage, firstNonEmpty(payload.Message, payload.Error))
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: installer rejected Core credentials", ErrUnavailable)
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		return fmt.Errorf("%w: %s", ErrConflict, firstNonEmpty(payload.Message, payload.Error))
	case http.StatusRequestEntityTooLarge:
		return ErrTooLarge
	case http.StatusUnprocessableEntity:
		return fmt.Errorf("%w: %s", ErrPackage, firstNonEmpty(payload.Message, payload.Error))
	default:
		return fmt.Errorf("%w: installer returned status %d", ErrUnavailable, status)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "installer rejected the request"
}

func validSlug(slug string) bool {
	if slug == "" || len(slug) > 63 {
		return false
	}
	for _, r := range slug {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return slug[0] != '-' && slug[len(slug)-1] != '-'
}
