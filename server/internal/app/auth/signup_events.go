package auth

// Sign-up events (docs/architecture/signup-activity.md): every account the
// public paths create, and every organization a person creates for
// themselves, is reported to the platform console's sign-up feed. Recording
// is best effort and never fails the sign-up.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/signupevent"
)

// SetSignupRecorder wires the sign-up event recorder.
func (s *AuthService) SetSignupRecorder(r signupevent.Recorder) { s.signups = r }

// SetSignupRecorder wires the sign-up event recorder.
func (s *OAuthService) SetSignupRecorder(r signupevent.Recorder) { s.signups = r }

// SetSignupRecorder wires the sign-up event recorder.
func (s *SSOService) SetSignupRecorder(r signupevent.Recorder) { s.signups = r }

func recordSignup(ctx context.Context, r signupevent.Recorder, e signupevent.Event) {
	if r != nil {
		r.Record(ctx, e)
	}
}
