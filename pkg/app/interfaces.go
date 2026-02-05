// Package app defines service interfaces for the application layer.
// These interfaces enable service wrapping for Enterprise/SaaS editions.
//
// Usage:
//
//	// OSS Core - Direct implementation
//	var svc app.AssetService = ossapp.NewAssetService(repo, log)
//
//	// Enterprise - Wrapped with RBAC/Audit
//	var svc app.AssetService = enterprise.NewAssetServiceWithRBAC(
//	    ossapp.NewAssetService(repo, log),
//	    rbacService,
//	    auditService,
//	)
package app

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ListResult is a generic paginated list result.
type ListResult[T any] struct {
	Items      []T   `json:"items"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	TotalPages int   `json:"total_pages"`
}

// ServiceContext provides common context for service operations.
type ServiceContext struct {
	TenantID shared.ID
	UserID   shared.ID
	IsAdmin  bool
}

// ServiceContextFromContext extracts ServiceContext from context.
// Returns nil if not found.
func ServiceContextFromContext(ctx context.Context) *ServiceContext {
	v := ctx.Value(serviceContextKey{})
	if v == nil {
		return nil
	}
	sc, ok := v.(*ServiceContext)
	if !ok {
		return nil
	}
	return sc
}

// ContextWithServiceContext adds ServiceContext to context.
func ContextWithServiceContext(ctx context.Context, sc *ServiceContext) context.Context {
	return context.WithValue(ctx, serviceContextKey{}, sc)
}

type serviceContextKey struct{}
