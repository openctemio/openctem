package feedstatus

import (
	"fmt"
	"math"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
)

// View is the status of one feed as the platform admin console reads it.
type View struct {
	Source  string
	Enabled bool
	State   State
	// LastSyncStatus is the raw status word of the last run (success, failed,
	// running, pending).
	LastSyncStatus string
	ErrorCode      string
	ErrorParams    map[string]string
	LastError      string // raw text: platform admin routes only
	LastAttemptAt  *time.Time
	LastSuccessAt  *time.Time
	FailingSince   *time.Time
	NextRunAt      *time.Time
	// RecordsChanged is what the last run wrote; CatalogRecords the size of
	// the stored catalog.
	RecordsChanged int
	CatalogRecords int64
	DataAsOf       *time.Time
	// DeliveredVia is the path that stored the data held (bundle or direct).
	DeliveredVia string
	Interval     time.Duration
	StaleAfter   time.Duration
	Bundle       *BundleDetail
}

// BundleDetail is the vulnerability bundle feed's own progress.
type BundleDetail struct {
	AppliedSequence uint64
	KeySetVersion   uint64
	RootKeyID       string
	Kind            string
	BundleCreatedAt *time.Time
	Sources         []BundleSource
}

// BundleSource is one upstream source named by the applied bundle.
type BundleSource struct {
	Name  string
	AsOf  *time.Time
	Fresh bool
}

// Build computes the view of one status row. catalog is the size of the
// stored catalog (for the bundle feed it is read from the row).
func Build(st *threatintel.SyncStatus, catalog int64, now time.Time) View {
	meta := st.Metadata()
	source := st.SourceName()
	v := View{
		Source:         source,
		Enabled:        st.IsEnabled(),
		LastError:      st.LastSyncError(),
		LastSyncStatus: st.LastSyncStatus().String(),
		LastAttemptAt:  st.LastSyncAt(),
		LastSuccessAt:  metaTime(meta[threatintel.MetaLastSuccessAt]),
		FailingSince:   metaTime(meta[threatintel.MetaFailingSince]),
		RecordsChanged: st.RecordsSynced(),
		CatalogRecords: catalog,
		Interval:       Interval(source),
		DeliveredVia:   metaString(meta["delivered_via"]),
		StaleAfter:     StaleAfter(source),
	}
	if c, ok := meta[threatintel.MetaErrorCode].(string); ok {
		v.ErrorCode = c
	}
	v.ErrorParams = metaStrings(meta[threatintel.MetaErrorParams])
	if st.LastSyncStatus() == threatintel.SyncStateFailed && v.ErrorCode == "" {
		v.ErrorCode = CodeFailed
	}

	in := Input{
		Source: source, Enabled: v.Enabled, Status: st.LastSyncStatus(), UpdatedAt: st.UpdatedAt(),
		LastSuccessAt: v.LastSuccessAt, FailingSince: v.FailingSince, ErrorCode: v.ErrorCode,
	}
	switch source {
	case SourceVulnfeed:
		d := &BundleDetail{
			AppliedSequence: metaUint(meta["applied_sequence"]),
			KeySetVersion:   metaUint(meta["keyset_version"]),
			Kind:            metaString(meta["kind"]),
			RootKeyID:       metaString(meta["root_key_id"]),
			BundleCreatedAt: metaTime(meta["bundle_created_at"]),
		}
		for _, raw := range metaList(meta["sources"]) {
			bs := BundleSource{Name: metaString(raw["name"]), AsOf: metaTime(raw["as_of"])}
			bs.Fresh = bs.AsOf != nil && now.Sub(*bs.AsOf) <= StaleAfterVulnfeed
			d.Sources = append(d.Sources, bs)
		}
		v.Bundle = d
		v.DataAsOf = d.BundleCreatedAt
		if v.CatalogRecords == 0 {
			if n := metaUint(meta["records"]); n <= math.MaxInt64 {
				v.CatalogRecords = int64(n)
			}
		}
		in.DataAsOf, in.HasAppliedData = d.BundleCreatedAt, d.AppliedSequence > 0
	case SourceEPSS:
		v.DataAsOf = metaTime(meta[MetaDataAsOf])
		if v.DataAsOf == nil {
			v.DataAsOf = v.LastSuccessAt
		}
	default:
		v.DataAsOf = v.LastSuccessAt
	}
	v.State = Compute(in, now)
	switch v.State {
	case StateRunning, StateUpToDate:
		v.ErrorCode, v.ErrorParams = "", nil
	case StateOff:
		v.ErrorCode, v.ErrorParams = CodeDisabled, nil
	}
	if v.Enabled && v.State != StateRunning && v.Interval > 0 {
		next := now
		if v.LastAttemptAt != nil && v.LastAttemptAt.Add(v.Interval).After(now) {
			next = v.LastAttemptAt.Add(v.Interval)
		}
		v.NextRunAt = &next
	}
	return v
}

func metaString(v any) string {
	s, _ := v.(string)
	return s
}

func metaTime(v any) *time.Time {
	s, ok := v.(string)
	if !ok || s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t, err = time.Parse("2006-01-02", s)
		if err != nil {
			return nil
		}
	}
	t = t.UTC()
	return &t
}

func metaUint(v any) uint64 {
	switch t := v.(type) {
	case float64:
		if t > 0 {
			return uint64(t)
		}
	case int:
		if t > 0 {
			return uint64(t)
		}
	case int64:
		if t > 0 {
			return uint64(t)
		}
	case uint64:
		return t
	}
	return 0
}

func metaStrings(v any) map[string]string {
	out := map[string]string{}
	switch t := v.(type) {
	case map[string]string:
		for k, x := range t {
			out[k] = x
		}
	case map[string]any:
		for k, x := range t {
			out[k] = fmt.Sprint(x)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func metaList(v any) []map[string]any {
	switch t := v.(type) {
	case []map[string]any:
		return t
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, x := range t {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}
