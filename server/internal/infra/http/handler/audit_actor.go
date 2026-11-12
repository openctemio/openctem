package handler

import (
	"context"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// auditActorEmail is the actor shown on an audit row. Password logins carry
// the email and no preferred username (that claim comes only from OIDC), so
// reading the username alone left the actor blank and the UI showed "System".
func auditActorEmail(ctx context.Context) string {
	if email := middleware.GetEmail(ctx); email != "" {
		return email
	}
	return middleware.GetUsername(ctx)
}
