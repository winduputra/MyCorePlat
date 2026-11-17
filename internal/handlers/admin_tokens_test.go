package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/middleware"
	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// fakeTokenService is an in-test TokenService.
type fakeTokenService struct {
	byTool map[uint64][]model.AccessToken
	nextID uint64

	createErr  error
	revokeErr  error
	listErr    error
	lastInput  service.AccessTokenInput
	createCall int
	revokeCall int
	plaintext  string
}

func newFakeTokenService() *fakeTokenService {
	return &fakeTokenService{
		byTool:    map[uint64][]model.AccessToken{},
		nextID:    1,
		plaintext: "tbpbj_newtok_secretsecretsecretsecretsecret",
	}
}

func (f *fakeTokenService) Create(_ context.Context, in service.AccessTokenInput, now time.Time) (string, *model.AccessToken, error) {
	f.createCall++
	f.lastInput = in
	if f.createErr != nil {
		return "", nil, f.createErr
	}
	tok := model.AccessToken{
		ID:               f.nextID,
		ToolID:           in.ToolID,
		TokenHash:        "hash-" + f.plaintext,
		TokenPrefix:      "newtok01",
		RecipientLabel:   nilIfEmpty(in.RecipientLabel),
		ExpiresAt:        in.ExpiresAt,
		CreatedByAdminID: in.CreatedByAdminID,
		CreatedAt:        now,
	}
	if tok.ExpiresAt.IsZero() {
		tok.ExpiresAt = now.Add(24 * time.Hour)
	}
	f.nextID++
	f.byTool[in.ToolID] = append(f.byTool[in.ToolID], tok)
	return f.plaintext, &tok, nil
}

func (f *fakeTokenService) Validate(_ context.Context, _ string, _ uint64, _ time.Time) (*model.AccessToken, error) {
	return nil, service.ErrAccessTokenInvalid
}

func (f *fakeTokenService) Revoke(_ context.Context, toolID, id uint64, now time.Time) error {
	f.revokeCall++
	if f.revokeErr != nil {
		return f.revokeErr
	}
	list := f.byTool[toolID]
	for i := range list {
		if list[i].ID == id {
			if list[i].RevokedAt != nil {
				return service.ErrAccessTokenNotFound
			}
			at := now
			list[i].RevokedAt = &at
			f.byTool[toolID] = list
			return nil
		}
	}
	return service.ErrAccessTokenNotFound
}

func (f *fakeTokenService) ListByTool(_ context.Context, toolID uint64) ([]model.AccessToken, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.byTool[toolID], nil
}

// fakeToolLookupForTokens is a minimal ToolService returning a fixed tool.
type fakeToolLookupForTokens struct {
	tool *model.Tool
	err  error
}

func (f *fakeToolLookupForTokens) List(context.Context) ([]model.Tool, error) { return nil, nil }
func (f *fakeToolLookupForTokens) Get(context.Context, uint64) (*model.Tool, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.tool, nil
}
func (f *fakeToolLookupForTokens) Create(context.Context, service.ToolInput) (*model.Tool, error) {
	return nil, nil
}
func (f *fakeToolLookupForTokens) Update(context.Context, uint64, service.ToolInput) (*model.Tool, error) {
	return nil, nil
}
func (f *fakeToolLookupForTokens) Delete(context.Context, uint64) error { return nil }

func newTokensHandler(t *testing.T, tokens TokenService, tool *model.Tool) *AdminTokensHandler {
	t.Helper()
	h, err := NewAdminTokensHandler(&fakeToolLookupForTokens{tool: tool}, tokens, AdminTokensOptions{})
	if err != nil {
		t.Fatalf("NewAdminTokensHandler: %v", err)
	}
	return h
}

// newTokensTestRouter registers the token routes and injects an authenticated
// admin identity into the context, mirroring what RequireAuth would do.
func newTokensTestRouter(t *testing.T, h *AdminTokensHandler, adminID uint64) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	inject := func(c *gin.Context) {
		c.Set("auth_admin_id", adminID)
		c.Set("auth_session", &model.AdminSession{ID: 1, AdminID: adminID})
		c.Next()
	}
	grp := r.Group("/admin", inject)
	grp.GET("/tools/:id/tokens", h.List)
	grp.GET("/tools/:id/tokens/new", h.New)
	grp.POST("/tools/:id/tokens", h.Create)
	grp.POST("/tools/:id/tokens/:token_id/revoke", h.Revoke)
	return r
}

func tokenFixtureTool() *model.Tool {
	return &model.Tool{
		ID:         5,
		Slug:       "image-compressor",
		Name:       "Image Compressor",
		AccessType: model.ToolAccessToken,
		Status:     model.ToolStatusActive,
	}
}

// TestTokensListRenders: the list page shows the create link and the empty state.
func TestTokensListRenders(t *testing.T) {
	h := newTokensHandler(t, newFakeTokenService(), tokenFixtureTool())
	r := newTokensTestRouter(t, h, 1)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/tools/5/tokens", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Buat Token") {
		t.Error("list page missing create link")
	}
	if !strings.Contains(body, "Belum ada token") {
		t.Error("list page missing empty state")
	}
}

// TestTokensListShowsPrefixNotPlaintext: a stored token shows only its prefix, and
// the page must never contain a plaintext token.
func TestTokensListShowsPrefixNotPlaintext(t *testing.T) {
	svc := newFakeTokenService()
	plaintext, _, err := svc.Create(context.Background(), service.AccessTokenInput{ToolID: 5, CreatedByAdminID: 1}, time.Now())
	if err != nil {
		t.Fatalf("seed token: %v", err)
	}
	h := newTokensHandler(t, svc, tokenFixtureTool())
	r := newTokensTestRouter(t, h, 1)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/tools/5/tokens", nil))

	body := rec.Body.String()
	if !strings.Contains(body, "newtok01") {
		t.Error("list page missing the token prefix")
	}
	if strings.Contains(body, plaintext) {
		t.Fatal("list page leaked a plaintext token")
	}
}

// TestTokensCreateShowsPlaintextOnce: the creation response contains the plaintext,
// but a subsequent list view does not.
func TestTokensCreateShowsPlaintextOnce(t *testing.T) {
	svc := newFakeTokenService()
	h := newTokensHandler(t, svc, tokenFixtureTool())
	r := newTokensTestRouter(t, h, 1)

	form := url.Values{"recipient_label": {"Bidang PBJ"}, "expires_at": {time.Now().Add(48 * time.Hour).Format("2006-01-02T15:04")}}
	req := httptest.NewRequest(http.MethodPost, "/admin/tools/5/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), svc.plaintext) {
		t.Fatal("creation response did not show the plaintext token")
	}
	if svc.createCall != 1 {
		t.Fatalf("Create calls = %d, want 1", svc.createCall)
	}
	// The creator must come from the session, not the form.
	if svc.lastInput.CreatedByAdminID != 1 {
		t.Fatalf("CreatedByAdminID = %d, want 1 (from session)", svc.lastInput.CreatedByAdminID)
	}
	if svc.lastInput.ToolID != 5 {
		t.Fatalf("ToolID = %d, want 5", svc.lastInput.ToolID)
	}

	// A fresh list must NOT contain the plaintext again.
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/admin/tools/5/tokens", nil))
	if strings.Contains(rec2.Body.String(), svc.plaintext) {
		t.Fatal("list page leaked a plaintext token after creation")
	}
}

// TestTokensCreateRejectsInvalidExpiry: a malformed date re-renders the form with
// an error and calls the service zero times.
func TestTokensCreateRejectsInvalidExpiry(t *testing.T) {
	svc := newFakeTokenService()
	h := newTokensHandler(t, svc, tokenFixtureTool())
	r := newTokensTestRouter(t, h, 1)

	form := url.Values{"expires_at": {"not-a-date"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/tools/5/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if svc.createCall != 0 {
		t.Fatalf("Create was called with an invalid expiry")
	}
}

// TestTokensCreateMapsExpiryErrors: a service expiry error re-renders 400 with a
// helpful message.
func TestTokensCreateMapsExpiryErrors(t *testing.T) {
	svc := newFakeTokenService()
	svc.createErr = service.ErrAccessTokenExpiryRequired
	h := newTokensHandler(t, svc, tokenFixtureTool())
	r := newTokensTestRouter(t, h, 1)

	form := url.Values{"expires_at": {time.Now().Add(time.Hour).Format("2006-01-02T15:04")}}
	req := httptest.NewRequest(http.MethodPost, "/admin/tools/5/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "kedaluwarsa") {
		t.Error("error message does not mention expiry")
	}
}

// TestTokensNewRendersForm: the create form targets the right action.
func TestTokensNewRendersForm(t *testing.T) {
	svc := newFakeTokenService()
	h := newTokensHandler(t, svc, tokenFixtureTool())
	r := newTokensTestRouter(t, h, 1)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/tools/5/tokens/new", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `action="/admin/tools/5/tokens"`) {
		t.Error("create form action is wrong")
	}
	if !strings.Contains(body, `name="expires_at"`) {
		t.Error("create form missing expiry field")
	}
}

// TestTokensRevokeHTMX: an HTMX revoke returns an empty body and revokes.
func TestTokensRevokeHTMX(t *testing.T) {
	svc := newFakeTokenService()
	if _, tok, err := svc.Create(context.Background(), service.AccessTokenInput{ToolID: 5, CreatedByAdminID: 1}, time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	} else if tok == nil {
		t.Fatal("seed returned nil token")
	}
	h := newTokensHandler(t, svc, tokenFixtureTool())
	r := newTokensTestRouter(t, h, 1)

	req := httptest.NewRequest(http.MethodPost, "/admin/tools/5/tokens/1/revoke", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HTMX revoke body = %q, want empty", rec.Body.String())
	}
	if svc.revokeCall != 1 {
		t.Fatalf("Revoke calls = %d, want 1", svc.revokeCall)
	}
}

// TestTokensRevokePlainRedirects: a plain POST redirects back to the list.
func TestTokensRevokePlainRedirects(t *testing.T) {
	svc := newFakeTokenService()
	_, _, _ = svc.Create(context.Background(), service.AccessTokenInput{ToolID: 5, CreatedByAdminID: 1}, time.Now())
	h := newTokensHandler(t, svc, tokenFixtureTool())
	r := newTokensTestRouter(t, h, 1)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/tools/5/tokens/1/revoke", nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/tools/5/tokens" {
		t.Fatalf("Location = %q", loc)
	}
}

// TestTokensRevokeUnknownReturns404: revoking a missing/cross-tool token is 404,
// revealing nothing about other tools.
func TestTokensRevokeUnknownReturns404(t *testing.T) {
	svc := newFakeTokenService()
	h := newTokensHandler(t, svc, tokenFixtureTool())
	r := newTokensTestRouter(t, h, 1)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/tools/5/tokens/999/revoke", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestTokensListUnknownToolReturns404: a missing tool (or a deleted one) is 404.
func TestTokensListUnknownToolReturns404(t *testing.T) {
	svc := newFakeTokenService()
	h, err := NewAdminTokensHandler(&fakeToolLookupForTokens{err: service.ErrToolNotFound}, svc, AdminTokensOptions{})
	if err != nil {
		t.Fatalf("NewAdminTokensHandler: %v", err)
	}
	r := newTokensTestRouter(t, h, 1)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/tools/5/tokens", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestTokensCreateRequiresAdminContext: without an admin identity the handler
// refuses to mint a token, so created_by_admin_id can never be forged.
func TestTokensCreateRequiresAdminContext(t *testing.T) {
	svc := newFakeTokenService()
	h := newTokensHandler(t, svc, tokenFixtureTool())
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/admin/tools/:id/tokens", h.Create) // no identity injected

	form := url.Values{"expires_at": {time.Now().Add(time.Hour).Format("2006-01-02T15:04")}}
	req := httptest.NewRequest(http.MethodPost, "/admin/tools/5/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if svc.createCall != 0 {
		t.Fatal("Create was called without an authenticated admin")
	}
}

var _ = middleware.AdminIDFromContext
