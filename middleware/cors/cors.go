package cors

import (
	"net/http"
	"strings"
)

// Middleware is a middleware that adds handling for CORS requests
type Middleware struct {
	handler                http.Handler
	allowAllOrigins        bool
	allowedOriginWhitelist map[string]struct{}
}

// MiddlewareOptions defines the options that may be used to configure the
// Middleware
type MiddlewareOptions struct {
	AllowAllOrigins        bool
	AllowedOriginWhitelist map[string]struct{}
}

// New construct a new Cors middleware
func New(handler http.Handler) *Middleware {
	return &Middleware{
		handler:                handler,
		allowAllOrigins:        true,
		allowedOriginWhitelist: map[string]struct{}{},
	}
}

// NewWithOptions constructs a new cors middleware
// using the options provided
func NewWithOptions(options *MiddlewareOptions, handler http.Handler) *Middleware {
	return &Middleware{
		handler:                handler,
		allowAllOrigins:        options.AllowAllOrigins,
		allowedOriginWhitelist: options.AllowedOriginWhitelist,
	}
}

func (c *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if origin, ok := r.Header["origin"]; ok && len(origin) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", "Set-Cookie")
		if c.allowAllOrigins {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else if _, ok := c.allowedOriginWhitelist[strings.ToLower(origin[0])]; ok {
			w.Header().Set("Access-Control-Allow-Origin", origin[0])
			w.Header().Set("Vary", "Origin")
		}
	}

	if _, ok := r.Header["Access-Control-Request-Method"]; r.Method == http.MethodOptions && ok {
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", r.Header.Get("Access-Control-Request-Headers"))
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
	} else {
		c.handler.ServeHTTP(w, r)
	}
}
