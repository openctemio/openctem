package apikey

import "context"

// Filter represents filtering options for listing API keys.
type Filter struct {
	TenantID  *ID
	UserID    *ID
	Status    *Status
	Search    string
	Page      int
	PerPage   int
	SortBy    string
	SortOrder string
}

// ListResult represents a paginated list of API keys.
type ListResult struct {
	Data       []*APIKey
	Total      int64
	Page       int
	PerPage    int
	TotalPages int
}

// Repository defines the interface for API key persistence.
type Repository interface {
	Create(ctx context.Context, key *APIKey) error
	GetByID(ctx context.Context, id, tenantID ID) (*APIKey, error)
	GetByHash(ctx context.Context, hash string) (*APIKey, error)
	List(ctx context.Context, filter Filter) (ListResult, error)
	Update(ctx context.Context, key *APIKey) error
	Delete(ctx context.Context, id, tenantID ID) error
}
