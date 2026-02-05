package shared

import (
	"database/sql/driver"
	"fmt"

	"github.com/google/uuid"
)

// ID represents a unique identifier for domain entities.
type ID struct {
	value uuid.UUID
}

// NewID creates a new random ID.
func NewID() ID {
	return ID{value: uuid.New()}
}

// IDFromString creates an ID from a string.
func IDFromString(s string) (ID, error) {
	parsed, err := uuid.Parse(s)
	if err != nil {
		return ID{}, fmt.Errorf("invalid id format: %w", err)
	}
	return ID{value: parsed}, nil
}

// MustIDFromString creates an ID from a string, panics on error.
func MustIDFromString(s string) ID {
	id, err := IDFromString(s)
	if err != nil {
		panic(err)
	}
	return id
}

// String returns the string representation of the ID.
func (id ID) String() string {
	return id.value.String()
}

// IsZero returns true if the ID is empty.
func (id ID) IsZero() bool {
	return id.value == uuid.Nil
}

// Equals checks if two IDs are equal.
func (id ID) Equals(other ID) bool {
	return id.value == other.value
}

// Value implements driver.Valuer for database serialization.
func (id ID) Value() (driver.Value, error) {
	return id.value.String(), nil
}

// Scan implements sql.Scanner for database deserialization.
func (id *ID) Scan(src any) error {
	switch v := src.(type) {
	case string:
		parsed, err := uuid.Parse(v)
		if err != nil {
			return err
		}
		id.value = parsed
	case []byte:
		parsed, err := uuid.ParseBytes(v)
		if err != nil {
			return err
		}
		id.value = parsed
	default:
		return fmt.Errorf("cannot scan type %T into ID", src)
	}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (id ID) MarshalJSON() ([]byte, error) {
	return []byte(`"` + id.String() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (id *ID) UnmarshalJSON(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("invalid id format")
	}
	s := string(data[1 : len(data)-1])
	parsed, err := uuid.Parse(s)
	if err != nil {
		return err
	}
	id.value = parsed
	return nil
}

// IDFromUUID creates an ID from a uuid.UUID.
func IDFromUUID(u uuid.UUID) ID {
	return ID{value: u}
}
