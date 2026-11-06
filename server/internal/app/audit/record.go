package audit

import (
	"context"
	"errors"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// ErrNotRecorded is returned by a service that undid an action because its
// audit event could not be recorded (fail closed). Handlers answer 503.
var ErrNotRecorded = errors.New("the action was not completed: it could not be audited")

// EventWriter is anything that persists one audit event (AuditService and the
// narrow interfaces services declare for it).
type EventWriter interface {
	LogEvent(ctx context.Context, actx AuditContext, event AuditEvent) error
}

// RecordOrWarn writes an audit event for an action that has ALREADY taken
// effect and cannot be undone by failing the request (the row is committed, the
// key is revoked). A write failure is never dropped silently: it is logged at
// WARN with the action and a sanitized error.
//
// Actions that must not happen without their audit row do not use this: they
// write the audit row in the same transaction (suppression rule delete), write
// the event FIRST and return its error (supportaccess.Service.StartSession), or
// undo the action and return ErrNotRecorded (creating a support grant, an API
// key or a stored credential).
//
// A nil log falls back to the logger on the context.
func RecordOrWarn(ctx context.Context, log *logger.Logger, w EventWriter, actx AuditContext, event AuditEvent) {
	err := w.LogEvent(ctx, actx, event)
	if err == nil {
		return
	}
	if log == nil {
		log = logger.FromContext(ctx)
	}
	log.Warn("audit event was not recorded",
		"action", logger.SanitizeValue(string(event.Action)),
		"resource_type", logger.SanitizeValue(string(event.ResourceType)),
		"resource_id", logger.SanitizeValue(event.ResourceID),
		"error", logger.SanitizeError(err),
	)
}
