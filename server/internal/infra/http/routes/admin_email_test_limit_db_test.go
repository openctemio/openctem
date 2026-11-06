package routes

import (
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/platformemail"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The test e-mail sends a real message through the stored server, so each
// administrator gets a few per minute; another administrator's budget is
// separate, and the throttle answers 429 without touching the mail server.
func TestAdminEmailTestIsThrottledPerAdmin_DB(t *testing.T) {
	const path = "/api/v1/admin/settings/email/test"
	h := newChainHarness(t, func(h *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		log := logger.NewNop()
		enc, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
		if err != nil {
			t.Fatal(err)
		}
		svc := platformemail.NewService(postgres.NewPlatformSettingRepository(db), enc, nil, log)
		h.AdminEmail = handler.NewAdminEmailHandler(svc, nil, "OpenCTEM", log)
		h.AdminEmailTestLimiter = middleware.NewAdminMappingRateLimiter(middleware.AdminMappingRateLimitConfig{WriteRequestsPerMin: 3}, log)
	})
	first := h.newAdmin(admin.AdminRoleSuperAdmin)
	first.verify()
	for i := 0; i < 3; i++ {
		if code, body := first.do(http.MethodPost, path, nil, true); code == http.StatusTooManyRequests {
			t.Fatalf("throttled after only %d tests: %s", i, body)
		}
	}
	if code, _ := first.do(http.MethodPost, path, nil, true); code != http.StatusTooManyRequests {
		t.Fatalf("4th test in a minute: %d, want 429", code)
	}
	second := h.newAdmin(admin.AdminRoleSuperAdmin)
	second.verify()
	if code, _ := second.do(http.MethodPost, path, nil, true); code == http.StatusTooManyRequests {
		t.Fatal("one administrator's tests used up another's budget")
	}
}
