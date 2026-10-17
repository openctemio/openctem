package handler

import (
	"net/http"
	"testing"
)

// collect, config_update and cancel steer a sensor like a scan command does,
// so only owners and administrators send them; health_check stays open to
// holders of sensors:commands:write.
func TestCommandCreate_SensorControlIsAdminOnly(t *testing.T) {
	for _, typ := range []string{"collect", "config_update", "cancel"} {
		f := newScanCommandFixture()
		if rec := f.post(t, false, `{"type":"`+typ+`"}`); rec.Code != http.StatusForbidden {
			t.Errorf("non-admin %s = %d, want 403", typ, rec.Code)
		}
		if len(f.repo.created) != 0 {
			t.Errorf("non-admin %s created a command", typ)
		}
		if rec := f.post(t, true, `{"type":"`+typ+`"}`); rec.Code == http.StatusForbidden {
			t.Errorf("admin %s refused: %s", typ, rec.Body.String())
		}
	}
	f := newScanCommandFixture()
	if rec := f.post(t, false, `{"type":"health_check"}`); rec.Code == http.StatusForbidden {
		t.Errorf("non-admin health_check refused: %s", rec.Body.String())
	}
}
