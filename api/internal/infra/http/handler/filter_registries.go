package handler

import (
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// FilterRegistries names the list query registries whose params are
// generated into swag annotations ("// filterspec-params: <name> ...").
func FilterRegistries() map[string]*filterspec.Registry {
	return map[string]*filterspec.Registry{
		"findings":            vulnerability.FindingFields,
		"web_endpoints":       webendpoint.Fields,
		"web_endpoint_events": webendpoint.EventFields,
	}
}
