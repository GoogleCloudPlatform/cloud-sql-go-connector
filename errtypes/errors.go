// Copyright 2021 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package errtypes

import "fmt"

type genericError struct {
	Message  string
	ConnName string
}

func (e *genericError) Error() string {
	return fmt.Sprintf("%v (connection name = %q)", e.Message, e.ConnName)
}

// NewClientError initializes a ClientError.
func NewClientError(msg, cn string) *ClientError {
	return &ClientError{
		genericError: &genericError{Message: "Client error: " + msg, ConnName: cn},
	}
}

// ClientError represents an incorrect request by the client. Client errors
// usually indicate a semantic error (e.g., the instance connection name is
// malformated, the SQL instance does not support the requested IP type, etc.)
type ClientError struct{ *genericError }

// NewServerError initializes a ServerError.
func NewServerError(msg, cn string) *ServerError {
	return &ServerError{
		genericError: &genericError{Message: "Server error: " + msg, ConnName: cn},
	}
}

// ServerError means the server returned with unexpected or invalid data. In
// general, this is an unexpected error and if a caller receives the error,
// there is likely a problem with the backend API or the instance itself (e.g.,
// missing certificates, invalid certificate encoding, region mismatch with the
// requested instance connection name, etc.)
type ServerError struct{ *genericError }

// APIError represents an error with the underlying network call to the SQL
// Admin API. APIErrors typically wrap Error types from the
// google.golang.org/api/googleapi package.
type APIError struct {
	Op       string
	ConnName string
	Message  string
	Err      error
}

func (e *APIError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("API error: Operation %s failed (connection name = %q): %v",
			e.Op, e.ConnName, e.Err)
	}
	return fmt.Sprintf("API error: Operation %s failed (connection name = %q)",
		e.Op, e.ConnName)
}

func (e *APIError) Unwrap() error { return e.Err }

// DialError represents a problem that occurred when trying to dial a SQL
// instance (e.g., a failure to set the keep-alive property, a TLS handshake
// failure, a missing certificate, etc.)
type DialError struct {
	ConnName string
	Message  string
	Err      error
}

func (e *DialError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("Dial error: %v (connection name = %q)", e.Message, e.ConnName)
	}
	return fmt.Sprintf("Dial error: %v (connection name = %q): %v", e.Message, e.ConnName, e.Err)
}

func (e *DialError) Unwrap() error { return e.Err }
