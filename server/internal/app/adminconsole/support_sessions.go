package adminconsole

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SupportSessionEnder ends the support sessions (support access) bound to a
// console session that just ended. It never returns an error: ending the
// console session must not depend on it.
type SupportSessionEnder interface {
	EndForConsoleSession(ctx context.Context, consoleSessionID shared.ID)
}

// SetSupportSessionEnder wires the support sessions to end with the console
// session that opened them (sign-out). Expiry and idle are covered by the
// support session sweeper.
func (s *Service) SetSupportSessionEnder(e SupportSessionEnder) { s.supportSessions = e }
