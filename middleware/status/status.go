package status

import (
	"github.com/chriscasola/gohttp/middleware/logger"
	"net/http"
	"strings"
)

// Middleware is a middleware that adds a "/status_check" endpoint
// to an HTTP server
type Middleware struct {
	handler http.Handler
}

// New construct a new StatusCheck middleware
func New(handler http.Handler) *Middleware {
	return &Middleware{handler: handler}
}

func (s *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/status_check") {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		logger.Print(r, "Got status check")
	} else {
		s.handler.ServeHTTP(w, r)
	}
}
