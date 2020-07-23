package cors

import (
	"net/http"
)

// Middleware is a middleware that adds handling for CORS requests
type Middleware struct {
	handler http.Handler
}

// New construct a new Cors middleware
func New(handler http.Handler) *Middleware {
	return &Middleware{handler: handler}
}

func (c *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "Set-Cookie")

	if _, ok := r.Header["Access-Control-Request-Method"]; r.Method == http.MethodOptions && ok {
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", r.Header.Get("Access-Control-Request-Headers"))
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
	} else {
		c.handler.ServeHTTP(w, r)
	}
}
