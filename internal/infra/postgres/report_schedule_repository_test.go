package postgres

import (
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// fakeReportScanner emulates database/sql row scanning so scan() can be
// exercised without a live database. It assigns the per-column values it is
// given to the scan destinations in order.
type fakeReportScanner struct {
	values []any
}

func (f *fakeReportScanner) Scan(dest ...any) error {
	for i, d := range dest {
		if i >= len(f.values) {
			break
		}
		src := f.values[i]
		switch p := d.(type) {
		case *string:
			*p = src.(string)
		case *[]byte:
			if src == nil {
				*p = nil
			} else {
				*p = src.([]byte)
			}
		case *sql.NullString:
			if src == nil {
				*p = sql.NullString{}
			} else {
				*p = sql.NullString{String: src.(string), Valid: true}
			}
		case **time.Time:
			if src == nil {
				*p = nil
			} else {
				t := src.(time.Time)
				*p = &t
			}
		case *bool:
			*p = src.(bool)
		case *int:
			*p = src.(int)
		case *time.Time:
			*p = src.(time.Time)
		}
	}
	return nil
}

// TestScan_NullLastStatus is a regression test: a schedule that has never run
// has a NULL last_status column. The scanner must map that to an empty string
// rather than erroring ("converting NULL to string is unsupported"), which
// previously 500'd the whole list endpoint once any schedule existed.
func TestScan_NullLastStatus(t *testing.T) {
	now := time.Now()
	repo := &ReportScheduleRepository{}

	// Column order mirrors scan(): id, tenant_id, name, report_type, format,
	// options, recipients, delivery_channel, integration_id, cron_expression,
	// timezone, is_active, last_run_at, last_status, next_run_at, run_count,
	// created_by, created_at, updated_at.
	sc := &fakeReportScanner{values: []any{
		shared.NewID().String(), // id
		shared.NewID().String(), // tenant_id
		"Weekly digest",         // name
		"executive_summary",     // report_type
		"html",                  // format
		[]byte(`{}`),            // options
		[]byte(`[]`),            // recipients
		"email",                 // delivery_channel
		nil,                     // integration_id (NULL)
		"0 8 * * 1",             // cron_expression
		"UTC",                   // timezone
		true,                    // is_active
		nil,                     // last_run_at (NULL — never run)
		nil,                     // last_status (NULL — the regression)
		nil,                     // next_run_at (NULL)
		0,                       // run_count
		nil,                     // created_by (NULL)
		now,                     // created_at
		now,                     // updated_at
	}}

	got, err := repo.scan(sc)
	if err != nil {
		t.Fatalf("scan returned error on NULL last_status: %v", err)
	}
	if got.LastStatus() != "" {
		t.Fatalf("expected empty LastStatus for NULL column, got %q", got.LastStatus())
	}
	if got.Name() != "Weekly digest" {
		t.Fatalf("unexpected name: %q", got.Name())
	}
}
