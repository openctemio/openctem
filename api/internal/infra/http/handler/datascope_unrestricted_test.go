package handler

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// unrestrictedRepo is a data-scope repository that is never asked: an owner
// resolves to "unrestricted" before any lookup.
type unrestrictedRepo struct{ datascope.Repository }

// unrestrictedDataScope is a wired enforcer whose caller is an organization
// owner (unrestricted), for handler tests that do not exercise scoping.
// Reads that follow the viewer's scope refuse with no enforcer at all.
func unrestrictedDataScope() *datascope.Enforcer {
	return datascope.New(unrestrictedRepo{}, func(context.Context) datascope.Caller {
		return datascope.Caller{UserID: "00000000-0000-0000-0000-0000000000aa", IsOwner: true}
	}, logger.NewNop())
}
