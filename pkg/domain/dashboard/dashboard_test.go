package dashboard

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
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
		widgets []Widget
		wantErr bool
	}{
		{name: "valid", dName: "My Board", widgets: okWidgets, wantErr: false},
		{name: "valid no widgets", dName: "Empty", widgets: nil, wantErr: false},
		{name: "empty name", dName: "", widgets: okWidgets, wantErr: true},
		{name: "whitespace name", dName: "   ", widgets: okWidgets, wantErr: true},
		{name: "name too long", dName: strings.Repeat("a", 101), widgets: okWidgets, wantErr: true},
		{name: "too many widgets", dName: "Board", widgets: manyWidgets, wantErr: true},
		{name: "empty widget_type", dName: "Board", widgets: []Widget{{WidgetType: "", W: 1, H: 1}}, wantErr: true},
		{name: "widget_type too long", dName: "Board", widgets: []Widget{{WidgetType: strings.Repeat("x", 65), W: 1, H: 1}}, wantErr: true},
		{name: "coordinate out of bounds", dName: "Board", widgets: []Widget{{WidgetType: "t", X: 0, Y: 0, W: 1001, H: 1}}, wantErr: true},
		{name: "negative coordinate", dName: "Board", widgets: []Widget{{WidgetType: "t", X: -1, Y: 0, W: 1, H: 1}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDashboard(tenantID, userID, tt.dName, tt.widgets)
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

func TestDashboardUpdate(t *testing.T) {
	d, err := NewDashboard(shared.NewID(), shared.NewID(), "orig", nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := d.Update("renamed", []Widget{{WidgetType: "t", W: 1, H: 1}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if d.Name() != "renamed" || len(d.Widgets()) != 1 {
		t.Fatalf("update did not apply: name=%q widgets=%d", d.Name(), len(d.Widgets()))
	}
	if err := d.Update("", nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected validation error on empty name, got %v", err)
	}
}
