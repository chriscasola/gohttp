package gohttp

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// SendJSON sends an http response with the given status code and
// serializes the given body as JSON and writes it into the response.
func SendJSON(w http.ResponseWriter, statusCode int, body interface{}) error {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(statusCode)

	encoder := json.NewEncoder(w)
	err := encoder.Encode(body)

	if err != nil {
		log.Printf("Error sending response: %v", err)
	}

	return err
}

// ReadJSON reads and deserializes JSON from the body of an
// HTTP request.
func ReadJSON(r *http.Request, dest interface{}) error {
	decoder := json.NewDecoder(r.Body)
	return decoder.Decode(dest)
}

// SendErrorResponse sends the given response code and logs the given
// message and error if not nil
func SendErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	w.WriteHeader(statusCode)
	fmt.Fprint(w, message)
	log.Printf("%v error=%v", message, err)
}
