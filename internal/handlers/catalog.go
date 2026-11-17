package handlers

import (
	"context"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// CatalogTools is the read side of the registry the public catalog needs.
type CatalogTools interface {
	List(ctx context.Context) ([]model.Tool, error)
}

// CatalogHandler renders the public homepage: the catalog of tools that an
// anonymous visitor may actually use.
//
// Only tools that are both ACTIVE and PUBLIC are published. Draft, disabled,
// maintenance and token-protected tools are never listed, matching the
// gateway's own enforcement so the homepage can never advertise something the
// gateway would refuse. The page carries no admin data and no secrets: it is
// safe to serve without authentication.
type CatalogHandler struct {
	tools CatalogTools
	tmpl  *template.Template
}

// NewCatalogHandler builds the catalog handler. The page template is parsed as
// its own template set (layout + one page) because every page defines a
// "content" block and multiple pages would otherwise collide.
func NewCatalogHandler(tools CatalogTools) (*CatalogHandler, error) {
	set, err := template.New("catalog").Funcs(adminTemplateFuncs()).ParseFS(
		templateFS,
		"templates/layouts/public.html.tmpl",
		"templates/pages/catalog.html.tmpl",
	)
	if err != nil {
		return nil, err
	}
	return &CatalogHandler{tools: tools, tmpl: set}, nil
}

// catalogCard is the minimal projection rendered on the homepage. It exposes
// only information already intended for the public (name, description, link).
type catalogCard struct {
	Slug        string
	Name        string
	Description string
	Category    string
	Link        string
}

type catalogData struct {
	Title string
	Cards []catalogCard
}

// Serve renders the public catalog. A repository failure degrades to an empty
// catalog (the page still renders) rather than surfacing an internal error.
func (h *CatalogHandler) Serve(c *gin.Context) {
	tools, err := h.tools.List(c.Request.Context())
	if err != nil {
		tools = nil
	}

	cards := make([]catalogCard, 0, len(tools))
	for i := range tools {
		t := &tools[i]
		if !isPubliclyListable(t) {
			continue
		}
		card := catalogCard{
			Slug: t.Slug,
			Name: t.Name,
			Link: "/t/" + t.Slug + "/",
		}
		if t.Description != nil {
			card.Description = *t.Description
		}
		if t.Category != nil {
			card.Category = *t.Category
		}
		cards = append(cards, card)
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Status(http.StatusOK)
	if err := h.tmpl.ExecuteTemplate(c.Writer, "catalog", catalogData{
		Title: "Katalog Tool",
		Cards: cards,
	}); err != nil {
		c.String(http.StatusInternalServerError, "render error")
	}
}

// isPubliclyListable reports whether a tool may appear in the public catalog:
// active, public-access and not soft-deleted.
func isPubliclyListable(t *model.Tool) bool {
	return t != nil &&
		t.DeletedAt == nil &&
		t.Status == model.ToolStatusActive &&
		t.AccessType == model.ToolAccessPublic
}
