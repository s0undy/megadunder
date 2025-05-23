package errors

import (
	"fmt"
)

// ErrorType represents the type of error
type ErrorType string

const (
	// ErrorTypeValidation represents validation errors
	ErrorTypeValidation ErrorType = "VALIDATION"
	// ErrorTypeSystem represents system/command execution errors
	ErrorTypeSystem ErrorType = "SYSTEM"
	// ErrorTypeConfiguration represents configuration errors
	ErrorTypeConfiguration ErrorType = "CONFIGURATION"
	// ErrorTypeNetwork represents network-related errors
	ErrorTypeNetwork ErrorType = "NETWORK"
)

// AppError represents an application error
type AppError struct {
	Type    ErrorType
	Message string
	Err     error
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the wrapped error
func (e *AppError) Unwrap() error {
	return e.Err
}

// NewValidationError creates a new validation error
func NewValidationError(message string, err error) *AppError {
	return &AppError{
		Type:    ErrorTypeValidation,
		Message: message,
		Err:     err,
	}
}

// NewSystemError creates a new system error
func NewSystemError(message string, err error) *AppError {
	return &AppError{
		Type:    ErrorTypeSystem,
		Message: message,
		Err:     err,
	}
}

// NewConfigError creates a new configuration error
func NewConfigError(message string, err error) *AppError {
	return &AppError{
		Type:    ErrorTypeConfiguration,
		Message: message,
		Err:     err,
	}
}

// NewNetworkError creates a new network error
func NewNetworkError(message string, err error) *AppError {
	return &AppError{
		Type:    ErrorTypeNetwork,
		Message: message,
		Err:     err,
	}
}
