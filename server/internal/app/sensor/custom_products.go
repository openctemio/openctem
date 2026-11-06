package sensor

// An organization's own sensor products (docs/rfcs/RFC-037 §13): the release
// lines an organization records for sensor products it builds itself, used
// only for that organization's own sensor verdicts.

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/versions"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SaveCustomProductInput records one product's release line.
type SaveCustomProductInput struct {
	TenantID     shared.ID
	Product      string
	Latest       string
	Min          string
	AuditContext *auditapp.AuditContext
}

func (s *SensorService) customProductStore() (sensordom.CustomProductStore, bool) {
	store, ok := s.repo.(sensordom.CustomProductStore)
	return store, ok
}

// ListCustomProducts returns the organization's products, by name.
func (s *SensorService) ListCustomProducts(ctx context.Context, tenantID shared.ID) ([]sensordom.CustomProduct, error) {
	store, ok := s.customProductStore()
	if !ok {
		return nil, shared.ErrNotFound
	}
	return store.ListCustomProducts(ctx, tenantID)
}

// CustomProductLines returns the organization's release lines by product
// token, for its own sensor verdicts (empty without a store).
func (s *SensorService) CustomProductLines(ctx context.Context, tenantID shared.ID) (map[string]sensordom.ReleaseLine, error) {
	store, ok := s.customProductStore()
	if !ok {
		return nil, nil
	}
	ps, err := store.ListCustomProducts(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]sensordom.ReleaseLine, len(ps))
	for _, p := range ps {
		out[p.Product] = p.Line()
	}
	return out, nil
}

// SaveCustomProduct validates and stores one product's release line and
// audits the change. A product the platform catalog lists (first-party or
// the operator's) is refused: its release line is not the organization's.
func (s *SensorService) SaveCustomProduct(ctx context.Context, in SaveCustomProductInput) (*sensordom.CustomProduct, error) {
	store, ok := s.customProductStore()
	if !ok {
		return nil, shared.ErrNotFound
	}
	p, err := sensordom.NormalizeCustomProduct(in.Product, in.Latest, in.Min)
	if err != nil {
		return nil, err
	}
	if _, listed := versions.LookupProduct(p.Product); listed {
		return nil, sensordom.ErrCustomProductReserved
	}
	p.TenantID, p.UpdatedAt = in.TenantID, s.now().UTC()
	if in.AuditContext != nil {
		if id, err := shared.IDFromString(in.AuditContext.ActorID); err == nil {
			p.UpdatedBy = &id
		}
	}
	if err := store.SaveCustomProduct(ctx, p); err != nil {
		return nil, err
	}
	s.auditCustomProduct(ctx, in.TenantID, p.Product,
		fmt.Sprintf("Sensor product %s: latest %s, minimum %s", p.Product, orNone(p.Latest), orNone(p.Min)), in.AuditContext)
	return &p, nil
}

// DeleteCustomProduct removes one product's release line (its sensors get
// only the compatibility verdicts again).
func (s *SensorService) DeleteCustomProduct(ctx context.Context, tenantID shared.ID, product string, actx *auditapp.AuditContext) error {
	store, ok := s.customProductStore()
	if !ok {
		return shared.ErrNotFound
	}
	p, err := sensordom.NormalizeCustomProduct(product, "", "")
	if err != nil {
		return sensordom.ErrCustomProductNotFound
	}
	if err := store.DeleteCustomProduct(ctx, tenantID, p.Product); err != nil {
		return err
	}
	s.auditCustomProduct(ctx, tenantID, p.Product, fmt.Sprintf("Sensor product %s removed", p.Product), actx)
	return nil
}

func (s *SensorService) auditCustomProduct(ctx context.Context, tenantID shared.ID, product, msg string, actx *auditapp.AuditContext) {
	if s.auditService == nil || actx == nil {
		return
	}
	s.logAudit(ctx, *actx, auditapp.NewSuccessEvent(audit.ActionSettingsUpdated, audit.ResourceTypeTenant, tenantID.String()).
		WithResourceName("sensor product: "+product).WithMessage(msg).WithSeverity(audit.SeverityLow).
		WithMetadata("product", product))
}

func orNone(v string) string {
	if v == "" {
		return "not set"
	}
	return v
}
