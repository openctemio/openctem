package app

// This file is a compatibility shim. The real AuditService, its value
// types (AuditEvent, AuditContext, etc.), and constructors live in
// internal/app/audit/ — grouped there so the audit domain lives in
// one folder instead of a single 800-line file in a flat package.
//
// The aliases below exist so every existing caller that uses
// `app.AuditService` / `app.NewSuccessEvent` / etc. continues to
// compile unchanged. Go type aliases are identical types (not
// wrappers): methods propagate, struct literals interchangeably, and
// interface assignability is preserved. Callers gradually migrate to
// importing internal/app/audit directly; when no external caller
// references the aliases, this shim can be deleted.
//
// DO NOT add new types here. New audit types must live in
// internal/app/audit/.

import "github.com/openctemio/api/internal/app/audit"

// Types.
type (
	AuditService       = audit.AuditService
	AuditContext       = audit.AuditContext
	AuditEvent         = audit.AuditEvent
	ListAuditLogsInput = audit.ListAuditLogsInput
	ChainBreak         = audit.ChainBreak
	ChainVerifyResult  = audit.ChainVerifyResult
)

// Constructors.
var (
	NewAuditService = audit.NewAuditService
	NewSuccessEvent = audit.NewSuccessEvent
	NewFailureEvent = audit.NewFailureEvent
	NewDeniedEvent  = audit.NewDeniedEvent
)
