package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cirunapp "github.com/openctemio/openctem/server/internal/app/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

const handlerPastedJWKS = `{"keys":[{"kty":"EC","kid":"gitlab-k1","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`

// trustKeysFake records what the handler passes for a trust configuration
// and answers like the service (domain validation included).
type trustKeysFake struct {
	CIAdminService
	got      cirunapp.TrustConfigInput
	tenant   shared.ID
	previews int
}

func (f *trustKeysFake) build(tenantID shared.ID, in cirunapp.TrustConfigInput) (*cirun.TrustConfig, error) {
	f.got, f.tenant = in, tenantID
	now := time.Now().UTC()
	c := &cirun.TrustConfig{ID: shared.NewID(), TenantID: tenantID, Name: in.Name, Provider: cirun.Provider(in.Provider),
		Issuer: in.Issuer, Rules: in.Rules, Enabled: true, CreatedAt: now, UpdatedAt: now, LastKeyID: "gitlab-k1"}
	if in.KeySource != nil {
		c.KeySource = cirun.KeySource(*in.KeySource)
	}
	if in.SigningKeys != nil {
		c.SigningKeys = *in.SigningKeys
		c.SigningKeysUpdatedAt = &now
	}
	c.Normalize()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (f *trustKeysFake) CreateTrustConfig(_ context.Context, tenantID shared.ID, in cirunapp.TrustConfigInput, _ cirunapp.Actor) (*cirun.TrustConfig, error) {
	return f.build(tenantID, in)
}

func (f *trustKeysFake) UpdateTrustConfig(_ context.Context, tenantID, _ shared.ID, in cirunapp.TrustConfigInput, _ cirunapp.Actor) (*cirun.TrustConfig, error) {
	return f.build(tenantID, in)
}

func (f *trustKeysFake) PreviewTrust(_ context.Context, tenantID shared.ID, in cirunapp.PreviewInput) (*cirunapp.PreviewResult, error) {
	f.got, f.tenant = in.Config, tenantID
	f.previews++
	return &cirunapp.PreviewResult{}, nil
}

func trustKeysBody(source, keys string) string {
	b, _ := json.Marshal(map[string]any{"name": "self-managed", "provider": "gitlab", "issuer": "https://gitlab.example.com",
		"rules": map[string]any{"owners": []string{"acme"}}, "key_source": source, "signing_keys": keys})
	return string(b)
}

// Pasted keys and the key source reach the service; the answer shows the
// kids, algorithm, paste date and last verifying key, and the document as
// stored (public data).
func TestCITrustConfig_PastedSigningKeysRoundTrip(t *testing.T) {
	tenant := shared.NewID()
	f := &trustKeysFake{}
	h := NewCIAdminHandler(f, assetScope{}, logger.NewNop())
	w := httptest.NewRecorder()
	h.CreateTrustConfig(w, tenantRequest(http.MethodPost, "/api/v1/ci/trust-configs", trustKeysBody("pasted", handlerPastedJWKS), tenant))
	if w.Code != http.StatusCreated {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if f.tenant != tenant || f.got.KeySource == nil || *f.got.KeySource != "pasted" || f.got.SigningKeys == nil || *f.got.SigningKeys != handlerPastedJWKS {
		t.Fatalf("service input = %+v (tenant %v)", f.got, f.tenant)
	}
	var out CITrustConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.KeySource != "pasted" || len(out.SigningKeyList) != 1 || out.SigningKeyList[0] != (CITrustSigningKey{KID: "gitlab-k1", Alg: "ES256"}) ||
		out.SigningKeysUpdatedAt == nil || out.LastKeyID != "gitlab-k1" || out.SigningKeys != handlerPastedJWKS {
		t.Fatalf("response = %+v", out)
	}

	// The preview verifies against the draft's pasted keys too.
	w = httptest.NewRecorder()
	h.PreviewTrustConfig(w, tenantRequest(http.MethodPost, "/api/v1/ci/trust-configs/preview",
		`{"id_token":"a.b.c","config":`+trustKeysBody("pasted", handlerPastedJWKS)+`}`, tenant))
	if w.Code != http.StatusOK || f.previews != 1 || f.got.SigningKeys == nil || *f.got.SigningKeys != handlerPastedJWKS {
		t.Fatalf("preview = %d, input %+v", w.Code, f.got)
	}

	// A change that omits both fields leaves them to the service (unchanged).
	w = httptest.NewRecorder()
	r := tenantRequest(http.MethodPut, "/", `{"name":"x","provider":"gitlab","rules":{"owners":["acme"]}}`, tenant)
	r.SetPathValue("id", shared.NewID().String())
	h.UpdateTrustConfig(w, r)
	if f.got.KeySource != nil || f.got.SigningKeys != nil {
		t.Fatalf("omitted fields were sent: %+v", f.got)
	}
}

// Every refused document is a 400 that says what is wrong, and private key
// material is never echoed back.
func TestCITrustConfig_PastedSigningKeysRefused(t *testing.T) {
	tenant := shared.NewID()
	h := NewCIAdminHandler(&trustKeysFake{}, assetScope{}, logger.NewNop())
	private := strings.Replace(handlerPastedJWKS, `"kty":"EC"`, `"kty":"EC","d":"c2VjcmV0LXByaXZhdGUta2V5"`, 1)
	for name, tc := range map[string]struct{ source, keys, want string }{
		"private key":         {"pasted", private, "private key material"},
		"not json":            {"pasted", "not json", "valid JSON"},
		"pasted without keys": {"pasted", "", "paste the provider's signing keys"},
		"unknown source":      {"sensor", handlerPastedJWKS, "key_source"},
		"too large":           {"pasted", fmt.Sprintf(`{"keys":[],"x":"%s"}`, strings.Repeat("a", 64<<10)), "64 KiB"},
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.CreateTrustConfig(w, tenantRequest(http.MethodPost, "/api/v1/ci/trust-configs", trustKeysBody(tc.source, tc.keys), tenant))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("%d %s, want 400 saying %q", w.Code, w.Body.String(), tc.want)
			}
			if strings.Contains(w.Body.String(), "c2VjcmV0LXByaXZhdGUta2V5") {
				t.Fatal("private key material echoed back")
			}
		})
	}
}

// unknownKeyCIService refuses every exchange as the service does when the
// token names a key the pasted set lacks.
type unknownKeyCIService struct{ fakeCIService }

func (unknownKeyCIService) Exchange(context.Context, cirunapp.ExchangeInput) (*cirunapp.ExchangeOutput, error) {
	return nil, &cirunapp.RefusedError{Code: cirunapp.RefuseUnknownKey, Message: cirunapp.UnknownKeyMessage}
}

// A token signed with a key that is not pasted is a 401 CI_TOKEN_UNKNOWN_KEY
// (never the retryable 503) that tells what to do.
func TestCIExchange_UnknownPastedKey(t *testing.T) {
	h := NewCIRunnerHandler(&unknownKeyCIService{}, logger.NewNop())
	w := httptest.NewRecorder()
	h.Exchange(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ci/oidc/exchange",
		strings.NewReader(`{"tenant_id":"`+shared.NewID().String()+`","id_token":"eyJhbGciOi.secret.sig"}`)))
	if w.Code != http.StatusUnauthorized || w.Header().Get("Retry-After") != "" {
		t.Fatalf("status %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	var out struct{ Code, Message string }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// The whole message survives the response's length and wording guards.
	if out.Code != "CI_TOKEN_UNKNOWN_KEY" || !strings.Contains(out.Message, cirunapp.UnknownKeyMessage) ||
		!strings.Contains(out.Message, "/oauth/discovery/keys") || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("body = %s", w.Body.String())
	}
}
