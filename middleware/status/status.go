package status

import (
	"github.com/chriscasola/gohttp/middleware/logger"
	"net/http"
	"strings"
)

// StatusCheck is a middleware that adds a "/status_check" endpoint
// to an HTTP server
type StatusCheck struct {
	handler http.Handler
}

// NewStatusCheck construct a new StatusCheck middleware
func NewStatusCheck(handler http.Handler) *StatusCheck {
	return &StatusCheck{handler: handler}
}

func (s *StatusCheck) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/status_check") {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		logger.Print(r, "Got status check")
	} else {
		s.handler.ServeHTTP(w, r)
	}
}
