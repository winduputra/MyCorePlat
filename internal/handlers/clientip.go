package handlers

import (
	"net"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/service"
)

// clientAddr returns the client address for c using the provided resolver.
//
// When resolver is nil (unit tests, or an explicit opt-out) it falls back to the
// TCP peer from RemoteAddr, so no client-supplied header is ever trusted by
// default. A configured resolver honours X-Forwarded-For only for requests that
// arrive from a configured trusted proxy.
func clientAddr(c *gin.Context, resolver *service.ClientIPResolver) string {
	if resolver != nil {
		return resolver.Resolve(c.Request)
	}
	return peerIP(c.Request)
}

// peerIP extracts the host portion of RemoteAddr, returning the raw value when
// it cannot be split (e.g. a bare IP without port).
func peerIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if host != "" {
			return host
		}
	}
	return r.RemoteAddr
}
