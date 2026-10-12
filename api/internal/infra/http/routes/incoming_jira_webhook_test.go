package routes

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// jiraSecrets maps an organization to its own Jira webhook secrets.
type jiraSecrets map[shared.ID][]string

func (s jiraSecrets) ListJiraWebhookSecrets(_ context.Context, tenantID shared.ID) ([]string, error) {
	return s[tenantID], nil
}

// The inbound Jira webhook accepts a delivery only when it is signed with a
// secret of the organization named in ?tenant=. There is no platform-wide
// secret: organization A's secret never verifies a delivery addressed to B,
// and an organization without a secret gets nothing through.
func TestIncomingJiraWebhook_PerOrganizationSecretOnly(t *testing.T) {
	tenantA, tenantB, tenantC := shared.NewID(), shared.NewID(), shared.NewID()
	resolver := jiraSecrets{
		tenantA: {"secret-of-a"},
		tenantB: {"secret-of-b"},
	}
	router := infrahttp.NewChiRouter()
	registerIncomingWebhookRoutes(router, &handler.JiraWebhookHandler{}, resolver, logger.NewNop())
	mux := router.(interface{ Handler() http.Handler }).Handler()

	send := func(tenant shared.ID, secret string) (code int) {
		defer func() {
			if recover() != nil {
				code = reachedHandler
			}
		}()
		body := `{"webhookEvent":"jira:issue_updated"}`
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		m := hmac.New(sha256.New, []byte(secret))
		_, _ = m.Write([]byte(ts + "." + body))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/incoming/jira?tenant="+tenant.String(), strings.NewReader(body))
		req.Header.Set("X-OpenCTEM-Signature", "sha256="+hex.EncodeToString(m.Sum(nil)))
		req.Header.Set("X-OpenCTEM-Timestamp", ts)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := send(tenantA, "secret-of-a"); code == http.StatusUnauthorized {
		t.Errorf("A's delivery signed with A's secret: got 401, want it past the signature check")
	}
	if code := send(tenantB, "secret-of-a"); code != http.StatusUnauthorized {
		t.Errorf("B's delivery signed with A's secret: got %d, want 401", code)
	}
	if code := send(tenantC, "secret-of-a"); code != http.StatusUnauthorized {
		t.Errorf("delivery for an organization without a secret: got %d, want 401", code)
	}
}
