package apispec

import (
	"context"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Record is a stored API description of an origin.
type Record struct {
	ID             shared.ID  `json:"id"`
	TenantID       shared.ID  `json:"-"`
	OriginAssetID  shared.ID  `json:"origin_asset_id"`
	Name           string     `json:"name"`
	Format         Format     `json:"format"`
	Title          string     `json:"title,omitempty"`
	SpecVersion    string     `json:"spec_version,omitempty"`
	Digest         string     `json:"digest"`
	SizeBytes      int        `json:"size_bytes"`
	OperationCount int        `json:"operation_count"`
	Truncated      int        `json:"truncated"`
	UploadedBy     *shared.ID `json:"uploaded_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Observed is one endpoint a scan observed on the origin, as drift reads it.
type Observed struct {
	EndpointID   shared.ID
	Method       string
	PathTemplate string
	LastStatus   int
	Sources      []string
	ParamNames   []string // "location:name"
}

// DriftItem is one difference.
type DriftItem struct {
	Method     string     `json:"method"`
	Path       string     `json:"path"`
	EndpointID *shared.ID `json:"endpoint_id,omitempty"`
	// Params are the parameter names a scan saw that the description does
	// not declare (param drift).
	Params []string `json:"params,omitempty"`
}

// Drift compares a description with what scans observed on its origin.
type Drift struct {
	// Shadow: observed, not declared (an undocumented endpoint).
	Shadow []DriftItem `json:"shadow"`
	// Orphan: declared, never observed.
	Orphan []DriftItem `json:"orphan"`
	// Zombie: declared deprecated, still answering 2xx.
	Zombie []DriftItem `json:"zombie"`
	// ParamDrift: declared and observed, with parameters the description
	// does not name.
	ParamDrift []DriftItem `json:"param_drift"`
}

// Repository stores descriptions. Every method is tenant-scoped.
type Repository interface {
	Create(ctx context.Context, r *Record, ops []Operation) error
	Get(ctx context.Context, tenantID, id shared.ID) (*Record, error)
	ListByOrigin(ctx context.Context, tenantID, originAssetID shared.ID, limit int) ([]*Record, error)
	Operations(ctx context.Context, tenantID, specID shared.ID) ([]Operation, error)
	Observed(ctx context.Context, tenantID, originAssetID shared.ID, limit int) ([]Observed, error)
	Delete(ctx context.Context, tenantID, id shared.ID) error
}

// isSpecOnly reports whether an observed endpoint was only ever seen in a
// description (never by a scan).
func isSpecOnly(sources []string) bool {
	if len(sources) == 0 {
		return false
	}
	for _, s := range sources {
		if s != "spec" {
			return false
		}
	}
	return true
}

// ComputeDrift compares the declared operations with the observed endpoints.
// An observed endpoint of method ANY matches any declared method on its
// path.
func ComputeDrift(ops []Operation, observed []Observed) Drift {
	d := Drift{Shadow: []DriftItem{}, Orphan: []DriftItem{}, Zombie: []DriftItem{}, ParamDrift: []DriftItem{}}
	declared := map[string]Operation{}
	declaredPaths := map[string]bool{}
	for _, o := range ops {
		declared[MatchKey(o.Method, o.Path)] = o
		declaredPaths[MatchKey("", o.Path)] = true
	}
	seen := map[string]bool{}
	for _, e := range observed {
		if isSpecOnly(e.Sources) {
			continue
		}
		key := MatchKey(e.Method, e.PathTemplate)
		op, ok := declared[key]
		if !ok && e.Method == "ANY" && declaredPaths[MatchKey("", e.PathTemplate)] {
			seen[MatchKey("", e.PathTemplate)] = true
			continue
		}
		id := e.EndpointID
		if !ok {
			d.Shadow = append(d.Shadow, DriftItem{Method: e.Method, Path: e.PathTemplate, EndpointID: &id})
			continue
		}
		seen[key] = true
		if op.Deprecated && e.LastStatus >= 200 && e.LastStatus <= 299 {
			d.Zombie = append(d.Zombie, DriftItem{Method: op.Method, Path: op.Path, EndpointID: &id})
		}
		have := map[string]bool{}
		for _, p := range op.Params {
			have[p.Location+":"+p.Name] = true
		}
		var extra []string
		for _, n := range e.ParamNames {
			if !have[n] {
				extra = append(extra, n)
			}
		}
		if len(extra) > 0 {
			sort.Strings(extra)
			d.ParamDrift = append(d.ParamDrift, DriftItem{Method: op.Method, Path: op.Path, EndpointID: &id, Params: extra})
		}
	}
	for _, o := range ops {
		if !seen[MatchKey(o.Method, o.Path)] && !seen[MatchKey("", o.Path)] {
			d.Orphan = append(d.Orphan, DriftItem{Method: o.Method, Path: o.Path})
		}
	}
	return d
}
