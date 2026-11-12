package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/apierror"
)

// Every error body carries the request id the response header carries, with
// no call-site change, and a hostile inbound id never reaches either place
// (nor the context that audit rows read).
func TestRequestID_ErrorBodyMatchesHeader(t *testing.T) {
	hostile := "x\"; DROP TABLE audit;--" + strings.Repeat("a", 100)
	cases := map[string]string{
		"absent":  "",
		"valid":   "trace-abc.123_X",
		"hostile": hostile,
		"toolong": strings.Repeat("a", 65),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			var ctxID string
			h := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctxID = GetRequestID(r.Context())
				apierror.NotFound("thing").WriteJSON(w)
			}))
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			if in != "" {
				req.Header.Set("X-Request-ID", in)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			var body apierror.Response
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body: %v", err)
			}
			hdr := rec.Header().Get("X-Request-ID")
			if body.RequestID == "" || body.RequestID != hdr || body.RequestID != ctxID {
				t.Fatalf("body %q header %q ctx %q must all match", body.RequestID, hdr, ctxID)
			}
			if !isValidRequestID(body.RequestID) {
				t.Fatalf("invalid id leaked: %q", body.RequestID)
			}
			if name == "valid" && body.RequestID != in {
				t.Fatalf("valid id should be kept, got %q", body.RequestID)
			}
		})
	}
}
