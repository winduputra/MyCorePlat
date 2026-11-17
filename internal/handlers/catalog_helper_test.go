package handlers

import (
	"net/http/httptest"

	"github.com/gin-gonic/gin"
)

// performRequest drives a gin engine with a bare request and returns the recorder.
func performRequest(r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
