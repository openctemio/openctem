package webhook

import "context"

// Filter represents filtering options for listing webhooks.
type Filter struct {
	TenantID  *ID
	Status    *Status
	EventType string
	Search    string
	Page      int
	PerPage   int
	SortBy    string
	SortOrder string
}

// ListResult represents a paginated list of webhooks.
type ListResult struct {
	Data       []*Webhook
	Total      int64
	Page       int
	PerPage    int
	TotalPages int
}

// DeliveryFilter represents filtering options for listing deliveries.
type DeliveryFilter struct {
	WebhookID *ID
	Status    *DeliveryStatus
	Page      int
	PerPage   int
}

// DeliveryListResult represents a paginated list of deliveries.
type DeliveryListResult struct {
	Data       []*Delivery
	Total      int64
	Page       int
	PerPage    int
	TotalPages int
}

// Repository defines the interface for webhook persistence.
type Repository interface {
	Create(ctx context.Context, w *Webhook) error
	GetByID(ctx context.Context, id, tenantID ID) (*Webhook, error)
	List(ctx context.Context, filter Filter) (ListResult, error)
	Update(ctx context.Context, w *Webhook) error
	Delete(ctx context.Context, id, tenantID ID) error
	ListDeliveries(ctx context.Context, filter DeliveryFilter) (DeliveryListResult, error)
}
