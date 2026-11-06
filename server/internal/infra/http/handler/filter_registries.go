package handler

import (
	"github.com/openctemio/openctem/server/pkg/domain/certificate"
	"github.com/openctemio/openctem/server/pkg/domain/exposure"
	"github.com/openctemio/openctem/server/pkg/domain/posture"
	"github.com/openctemio/openctem/server/pkg/domain/technology"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

// FilterRegistries names the list query registries whose params are
// generated into swag annotations ("// filterspec-params: <name> ...").
func FilterRegistries() map[string]*filterspec.Registry {
	return map[string]*filterspec.Registry{
		"findings":               vulnerability.FindingFields,
		"web_endpoints":          webendpoint.Fields,
		"certificates":           certificate.Fields,
		"technologies":           technology.Fields,
		"exposure_items":         exposure.ItemFields,
		"attack_surface_posture": posture.Fields,
		"web_endpoint_events":    webendpoint.EventFields,
	}
}
