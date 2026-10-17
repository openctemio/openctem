package postgres

import commandapp "github.com/openctemio/openctem/api/internal/app/command"

// The shared claim path finds its repository methods by an interface
// assertion and fails closed (claims nothing) when the repository does not
// implement them; a rename on one side once made every shared claim return
// nothing without an error. These compile-time checks keep both sides in
// step.
var (
	_ commandapp.SharedClaimer     = (*CommandRepository)(nil)
	_ commandapp.SharedGrantReader = (*SensorGrantRepository)(nil)
)
