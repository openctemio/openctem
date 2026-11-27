package ticketmap

import "github.com/openctemio/openctem/server/pkg/domain/shared"

// FieldError refuses one field of a mapping request and says why, so the
// answer names the field (TICKET_MAPPING_INVALID_FIELD, details.params.field)
// instead of a generic "invalid request". Field is the request's JSON name;
// Reason is our own sentence, never a value from the request.
type FieldError struct {
	Field  string
	Reason string
}

// FieldInvalid returns the refusal of field for reason.
func FieldInvalid(field, reason string) *FieldError {
	return &FieldError{Field: field, Reason: reason}
}

func (e *FieldError) Error() string {
	return shared.ErrValidation.Error() + ": " + e.Field + ": " + e.Reason
}

// Unwrap makes a FieldError a validation error.
func (e *FieldError) Unwrap() error { return shared.ErrValidation }

// Sentence is the message a person reads: "<field> is not valid: <reason>."
func (e *FieldError) Sentence() string {
	return e.Field + " is not valid: " + e.Reason + "."
}
