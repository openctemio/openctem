package handler

import (
	"context"
	"errors"
	"net/http"

	appimportmapping "github.com/openctemio/openctem/api/internal/app/importmapping"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/importmapping"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ImportMappingResolver resolves "format=mapping:<ref>[@<version>]" in the
// caller's organization (appimportmapping.Service).
type ImportMappingResolver interface {
	Resolve(ctx context.Context, tenantID shared.ID, ref importmapping.FormatRef) (*appimportmapping.Resolved, error)
}

// CodeUnknownMapping answers a format naming no mapping of the organization.
const CodeUnknownMapping apierror.Code = "unknown_mapping"

// resolveMappingFormat resolves a "mapping:" format. ok is false when the
// format names no mapping (another format, handled by the caller). A
// mapping of another organization, by name or id, is unknown: the tenant
// comes from the authenticated principal, never from the request.
func resolveMappingFormat(ctx context.Context, res ImportMappingResolver, tenantID shared.ID, format string) (*appimportmapping.Resolved, bool, *apierror.Error) {
	ref, ok, err := importmapping.ParseFormat(format)
	if !ok {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, apierror.BadRequest("format must be mapping:<name or id>[@<version>]")
	}
	if res == nil {
		return nil, true, apierror.BadRequest("import mappings are not available")
	}
	r, err := res.Resolve(ctx, tenantID, ref)
	if errors.Is(err, importmapping.ErrUnknownMapping) {
		return nil, true, apierror.New(http.StatusBadRequest, CodeUnknownMapping, "the format names no import mapping of this organization")
	}
	var ve *appimportmapping.ValidationError
	if errors.As(err, &ve) {
		return nil, true, apierror.ValidationFailed("the mapping no longer passes validation; save a new version", map[string]any{"errors": ve.Problems})
	}
	if err != nil {
		return nil, true, apierror.InternalServerError("the import mapping could not be read")
	}
	return r, true, nil
}
