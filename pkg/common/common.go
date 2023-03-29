package common

import "fmt"

type HttpResponseError struct {
	Type       string
	StatusCode int
}

type JsonResponse struct {
	Type    string
	Payload string
	Error   error
}

func (err *HttpResponseError) Error() string {
	if err.Type != "" {
		return fmt.Sprintf("%s: status %d", err.Type, err.StatusCode)
	}
	return fmt.Sprintf("status %d", err.StatusCode)
}
