package scm

import (
	"errors"
	"fmt"
	"testing"
)

func TestSCMError_Is_MatchesWrappedByCode(t *testing.T) {
	wrapped := ErrAuthFailed.Wrap(fmt.Errorf("invalid or expired token"))
	if !errors.Is(wrapped, ErrAuthFailed) {
		t.Error("errors.Is(ErrAuthFailed.Wrap(...), ErrAuthFailed) should be true")
	}
	if errors.Is(wrapped, ErrNotFound) {
		t.Error("a wrapped auth error must not match a different sentinel")
	}
}
