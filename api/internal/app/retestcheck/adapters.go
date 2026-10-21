package retestcheck

// Adapters between the retest check service, the template library and the
// retest service (wired in cmd/server).

import (
	"context"
	"encoding/base64"

	"github.com/openctemio/openctem/api/internal/app"
	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// LibraryTemplates is the template library seen by the retestcheck
// service: every create and edit goes through the scanner template
// service (validation, quota, approval for sensors, signature).
type LibraryTemplates struct {
	Svc *app.ScannerTemplateService
}

func (t LibraryTemplates) Get(ctx context.Context, tenantID, templateID shared.ID) (*scannertemplate.ScannerTemplate, error) {
	return t.Svc.GetTemplate(ctx, tenantID.String(), templateID.String())
}

func (t LibraryTemplates) Create(ctx context.Context, tenantID, userID shared.ID, name string, content []byte, tags []string) (*scannertemplate.ScannerTemplate, error) {
	return t.Svc.CreateTemplate(ctx, app.CreateScannerTemplateInput{
		TenantID: tenantID.String(), UserID: userID.String(), Name: name,
		TemplateType: string(scannertemplate.TemplateTypeNuclei),
		Description:  "Retest check of a finding",
		Content:      base64.StdEncoding.EncodeToString(content), Tags: tags,
	})
}

func (t LibraryTemplates) UpdateContent(ctx context.Context, tenantID, templateID, userID shared.ID, content []byte) (*scannertemplate.ScannerTemplate, error) {
	cur, err := t.Svc.GetTemplate(ctx, tenantID.String(), templateID.String())
	if err != nil {
		return nil, err
	}
	return t.Svc.UpdateTemplate(ctx, app.UpdateScannerTemplateInput{
		TenantID: tenantID.String(), TemplateID: templateID.String(), UserID: userID.String(),
		Description: cur.Description, Tags: cur.Tags,
		Content: base64.StdEncoding.EncodeToString(content),
	})
}

func (t LibraryTemplates) Delete(ctx context.Context, tenantID, templateID shared.ID) error {
	return t.Svc.DeleteTemplate(ctx, tenantID.String(), templateID.String())
}

// RetestSource hands a finding's runnable check to the retest service.
type RetestSource struct {
	Svc *Service
}

func (c RetestSource) RunnableCheck(ctx context.Context, tenantID, findingID shared.ID) (*retestapp.CustomCheck, error) {
	r, err := c.Svc.RunnableCheck(ctx, tenantID, findingID)
	if err != nil || r == nil {
		return nil, err
	}
	return &retestapp.CustomCheck{CheckID: r.CheckID, TemplateID: r.TemplateID, TemplateName: r.TemplateName,
		NucleiID: r.NucleiID, Content: r.Content, Digest: r.Digest, Path: r.Path}, nil
}

func (c RetestSource) CalibratedDigest(ctx context.Context, tenantID, findingID, checkID shared.ID) (string, error) {
	return c.Svc.CalibratedDigest(ctx, tenantID, findingID, checkID)
}

func (c RetestSource) MarkCalibrated(ctx context.Context, tenantID, checkID shared.ID, digest string) error {
	return c.Svc.MarkCalibrated(ctx, tenantID, checkID, digest)
}

var (
	_ TemplateStore         = LibraryTemplates{}
	_ retestapp.CheckSource = RetestSource{}
)
