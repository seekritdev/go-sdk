package seekrit

import "fmt"

// CryptoError means a token, wrapped DEK, or secret ciphertext could not be
// parsed or decrypted. It is deliberately unspecific — a decrypt failure does
// not distinguish "wrong key" from "tampered data" from "mismatched context".
type CryptoError struct {
	msg   string
	cause error
}

func (e *CryptoError) Error() string { return "seekrit: " + e.msg }

func (e *CryptoError) Unwrap() error { return e.cause }

// APIError is returned when the resolve API responds with a non-2xx status.
type APIError struct {
	// Status is the HTTP status code.
	Status int
	// Code is the error.code from the API body (e.g. "unauthorized",
	// "forbidden", "not_found"), or "internal" if the body did not parse.
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("seekrit: %d %s: %s", e.Status, e.Code, e.Message)
}
