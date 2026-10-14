package sensor

// Declared tools (RFC-092): a tool a sensor declares in its
// manifest, with a valid contract, joins its organization's tool catalog,
// so the platform shows it, offers its settings form and runs scans with it
// without a platform change. The catalog row is a projection of the tool's
// descriptor (tooldom.NewDeclaredTool); it grants the tool nothing.

import (
	"context"
	"encoding/json"
	"errors"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
)

// SetDeclaredTools sets the store a manifest's declared tools are projected
// into (nil: none are; a tool must then already be in the catalog).
func (s *SensorService) SetDeclaredTools(store tooldom.DeclaredStore) { s.declaredTools = store }

// projectDeclaredTools adds the tools a's manifest declares to a's
// organization's catalog, or refreshes their rows from a newer descriptor.
// A platform sensor (no organization) projects nothing: it runs only the
// tools the platform's catalog lists; nor does a sensor that is not active. Failures are logged: the manifest is
// still stored, without the tools the catalog does not know.
func (s *SensorService) projectDeclaredTools(ctx context.Context, a *sensordom.Sensor, m sensordom.Manifest) {
	if s.declaredTools == nil || a == nil || a.TenantID == nil || a.Status != sensordom.SensorStatusActive {
		return
	}
	for _, dt := range m.DeclaredTools() {
		d := declarationOf(dt)
		cur, err := s.declaredTools.GetByTenantAndName(ctx, *a.TenantID, dt.Name)
		switch {
		case err == nil:
			if cur.RefreshDeclaration(d, newerVersion) {
				if err := s.declaredTools.UpdateDeclared(ctx, cur); err != nil {
					s.logger.Warn("declared tool not refreshed", "sensor_id", a.ID.String(), "tool", dt.Name, "error", err)
				}
			}
		case errors.Is(err, shared.ErrNotFound):
			t, err := tooldom.NewDeclaredTool(*a.TenantID, d)
			if err != nil {
				continue
			}
			created, err := s.declaredTools.CreateDeclared(ctx, t)
			if err != nil {
				s.logger.Warn("declared tool not added to the catalog", "sensor_id", a.ID.String(), "tool", dt.Name, "error", err)
				continue
			}
			if created {
				s.logger.Info("declared tool added to the catalog", "sensor_id", a.ID.String(), "tool", dt.Name,
					"digest", dt.Contract.Digest)
			}
		default:
			s.logger.Warn("declared tool lookup failed", "sensor_id", a.ID.String(), "tool", dt.Name, "error", err)
		}
	}
}

// newerVersion reports whether a is a newer version than b.
func newerVersion(a, b string) bool { return sensordom.CompareVersions(a, b) > 0 }

// declarationOf reads what the catalog shows of a declared tool from its
// descriptor. Unreadable members are left empty.
func declarationOf(dt sensordom.DeclaredTool) tooldom.Declaration {
	var desc struct {
		Version      string         `json:"version"`
		Description  string         `json:"description"`
		Consumes     []string       `json:"consumes"`
		Config       map[string]any `json:"config"`
		Presentation *struct {
			DisplayName string `json:"display_name"`
			Category    string `json:"category"`
			Icon        string `json:"icon"`
		} `json:"presentation"`
	}
	_ = json.Unmarshal(dt.Contract.Descriptor, &desc)
	d := tooldom.Declaration{
		Name:         dt.Name,
		Version:      firstNonEmpty(desc.Version, dt.Contract.Version),
		Description:  desc.Description,
		Implements:   dt.Contract.Implements,
		Consumes:     firstNonEmptyList(desc.Consumes, dt.Contract.Consumes),
		ConfigSchema: desc.Config,
		Digest:       dt.Contract.Digest,
	}
	if p := desc.Presentation; p != nil {
		d.DisplayName, d.Category, d.Icon = p.DisplayName, p.Category, p.Icon
	}
	return d
}

func firstNonEmptyList(a, b []string) []string {
	if len(a) > 0 {
		return a
	}
	return b
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
