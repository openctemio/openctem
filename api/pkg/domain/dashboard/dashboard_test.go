package dashboard

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestNewDashboard(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()

	okWidgets := []Widget{{WidgetType: "risk_summary", X: 0, Y: 0, W: 4, H: 2}}

	manyWidgets := make([]Widget, 51)
	for i := range manyWidgets {
		manyWidgets[i] = Widget{WidgetType: "tile", X: 0, Y: 0, W: 1, H: 1}
	}

	tests := []struct {
		name    string
		dName   string
		desc    string
		columns int
		widgets []Widget
		wantErr bool
	}{
		{name: "valid", dName: "My Board", columns: 3, widgets: okWidgets, wantErr: false},
		{name: "valid no widgets", dName: "Empty", columns: 2, widgets: nil, wantErr: false},
		{name: "zero columns defaults", dName: "Defaulted", columns: 0, widgets: okWidgets, wantErr: false},
		{name: "empty name", dName: "", columns: 2, widgets: okWidgets, wantErr: true},
		{name: "whitespace name", dName: "   ", columns: 2, widgets: okWidgets, wantErr: true},
		{name: "name too long", dName: strings.Repeat("a", 101), columns: 2, widgets: okWidgets, wantErr: true},
		{name: "description too long", dName: "Board", desc: strings.Repeat("d", 501), columns: 2, widgets: okWidgets, wantErr: true},
		{name: "columns too low", dName: "Board", columns: -1, widgets: okWidgets, wantErr: true},
		{name: "columns too high", dName: "Board", columns: 5, widgets: okWidgets, wantErr: true},
		{name: "too many widgets", dName: "Board", columns: 2, widgets: manyWidgets, wantErr: true},
		{name: "empty widget_type", dName: "Board", columns: 2, widgets: []Widget{{WidgetType: "", W: 1, H: 1}}, wantErr: true},
		{name: "widget_type too long", dName: "Board", columns: 2, widgets: []Widget{{WidgetType: strings.Repeat("x", 65), W: 1, H: 1}}, wantErr: true},
		{name: "coordinate out of bounds", dName: "Board", columns: 2, widgets: []Widget{{WidgetType: "t", X: 0, Y: 0, W: 1001, H: 1}}, wantErr: true},
		{name: "negative coordinate", dName: "Board", columns: 2, widgets: []Widget{{WidgetType: "t", X: -1, Y: 0, W: 1, H: 1}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDashboard(tenantID, userID, tt.dName, tt.desc, tt.columns, tt.widgets)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("expected ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Name() != strings.TrimSpace(tt.dName) {
				t.Fatalf("name = %q, want %q", d.Name(), strings.TrimSpace(tt.dName))
			}
			wantCols := tt.columns
			if wantCols == 0 {
				wantCols = 2 // defaultColumns
			}
			if d.Columns() != wantCols {
				t.Fatalf("columns = %d, want %d", d.Columns(), wantCols)
			}
			if d.IsDefault() {
				t.Fatalf("new dashboard must not be default")
			}
			if d.Widgets() == nil {
				t.Fatalf("widgets must never be nil")
			}
			if !d.TenantID().Equals(tenantID) || !d.UserID().Equals(userID) {
				t.Fatalf("scope not set from constructor args")
			}
		})
	}
}

func TestDashboardDescriptionAndColumnsRoundTrip(t *testing.T) {
	d, err := NewDashboard(shared.NewID(), shared.NewID(), "Board", "  a helpful note  ", 4, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if d.Description() != "a helpful note" {
		t.Fatalf("description = %q, want trimmed %q", d.Description(), "a helpful note")
	}
	if d.Columns() != 4 {
		t.Fatalf("columns = %d, want 4", d.Columns())
	}

	// Reconstruct preserves the persisted values.
	r := Reconstruct(d.ID(), d.TenantID(), d.UserID(), "Board", "note", 3, false, nil, d.CreatedAt(), d.UpdatedAt())
	if r.Description() != "note" || r.Columns() != 3 {
		t.Fatalf("reconstruct lost fields: desc=%q cols=%d", r.Description(), r.Columns())
	}
	// A zero column_count from an old row falls back to the default.
	r0 := Reconstruct(d.ID(), d.TenantID(), d.UserID(), "Board", "", 0, false, nil, d.CreatedAt(), d.UpdatedAt())
	if r0.Columns() != 2 {
		t.Fatalf("reconstruct zero columns = %d, want default 2", r0.Columns())
	}
}

func TestDashboardUpdate(t *testing.T) {
	d, err := NewDashboard(shared.NewID(), shared.NewID(), "orig", "", 2, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := d.Update("renamed", "new desc", 3, []Widget{{WidgetType: "t", W: 1, H: 1}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if d.Name() != "renamed" || len(d.Widgets()) != 1 {
		t.Fatalf("update did not apply: name=%q widgets=%d", d.Name(), len(d.Widgets()))
	}
	if d.Description() != "new desc" || d.Columns() != 3 {
		t.Fatalf("update did not apply desc/cols: desc=%q cols=%d", d.Description(), d.Columns())
	}
	if err := d.Update("", "", 2, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected validation error on empty name, got %v", err)
	}
	if err := d.Update("ok", strings.Repeat("d", 501), 2, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected validation error on long description, got %v", err)
	}
	if err := d.Update("ok", "", 9, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected validation error on columns out of range, got %v", err)
	}
}
