package logger

import (
	"context"
	"github.com/satori/go.uuid"
	"log"
	"net/http"
)

type contextKey int

const requestIDContextKey contextKey = 0

// GetRequestIDFromContext returns the request ID associated
// with the request
func getRequestIDFromContext(ctx context.Context) (string, bool) {
	requestID, ok := ctx.Value(requestIDContextKey).(string)
	return requestID, ok
}

// Middleware is a middleware that reads the
// x-request-id header from incoming requests and makes
// it available in the context. If no ID header is present
// a random ID will be generated. The middleware also adds
// the header onto the response.
type Middleware struct {
	handler http.Handler
}

// New construct a new request ID middleware
func New(handler http.Handler) *Middleware {
	return &Middleware{handler: handler}
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("x-request-id")

	if requestID == "" {
		requestID = uuid.NewV4().String()
	}

	requestContext := context.WithValue(r.Context(), requestIDContextKey, requestID)

	m.handler.ServeHTTP(w, r.WithContext(requestContext))
}

// Print is similar to log.Print except the request ID will be
// prepended to the log message.
func Print(r *http.Request, v ...interface{}) {
	requestID, ok := getRequestIDFromContext(r.Context())
	if ok {
		message := append([]interface{}{"request_id=" + requestID + " message="}, v...)
		log.Print(message...)
	} else {
		log.Print(v...)
	}
}

// Printf is similar to log.Print except the request ID will be
// prepended to the log message.
func Printf(r *http.Request, s string, v ...interface{}) {
	requestID, ok := getRequestIDFromContext(r.Context())
	if ok {
		message := "request_id=" + requestID + " message=" + s
		log.Printf(message, v...)
	} else {
		log.Printf(s, v...)
	}
}
