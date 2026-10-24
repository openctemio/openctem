package apierror

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// leakPatterns is what a response message must never carry: entity ids,
// SQL and driver text, dial errors, loopback hosts, file paths, Go runtime
// and encoding text.
var leakPatterns = map[string]*regexp.Regexp{
	"uuid":      regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	"sql":       regexp.MustCompile(`(?i)sqlstate|pq: |duplicate key|violates|constraint "|relation "`),
	"network":   regexp.MustCompile(`(?i)dial tcp|connection refused|no such host|i/o timeout|context deadline`),
	"loopback":  regexp.MustCompile(`127\.0\.0\.1|localhost:\d`),
	"path":      regexp.MustCompile(`/(home|var|tmp|app|etc)/`),
	"goruntime": regexp.MustCompile(`(?i)\.go:\d+|nil pointer|go struct field|%!|<nil>`),
	"prefix":    regexp.MustCompile(`(?i)^validation error:`),
}

// leakSamples are messages call sites produce today by passing err.Error()
// or formatting an id (research inventory, 2026-10).
var leakSamples = []struct {
	name   string
	status int
	code   Code
	msg    string
}{
	{"jira no credentials", 422, CodeBadRequest, "Connection test failed: integration 99999999-9999-4999-8999-999999999999 has no credentials"},
	{"sentinel prefix and id", 400, CodeBadRequest, "validation error: finding 3f1c2a9e-1b2c-4d5e-8f90-a1b2c3d4e5f6 is not in scope"},
	{"id in parentheses", 400, CodeBadRequest, "validation error: the issue type chosen for Bug issues (id 3f1c2a9e-1b2c-4d5e-8f90-a1b2c3d4e5f6) does not exist in project SEC"},
	{"pg unique", 409, CodeConflict, `create asset: ERROR: duplicate key value violates unique constraint "assets_tenant_name_key" (SQLSTATE 23505)`},
	{"pq", 400, CodeBadRequest, `pq: invalid input syntax for type uuid: "abc"`},
	{"dial", 400, CodeBadRequest, "Get \"http://10.1.2.3:8080/rest/api\": dial tcp 10.1.2.3:8080: connect: connection refused"},
	{"dns", 400, CodeBadRequest, "lookup jira.internal on 127.0.0.11:53: no such host"},
	{"deadline", 400, CodeBadRequest, "context deadline exceeded"},
	{"path", 400, CodeBadRequest, "open /var/lib/openctem/uploads/x.json: no such file or directory"},
	{"json decode", 400, CodeBadRequest, "json: cannot unmarshal string into Go struct field CreateRequest.port of type int"},
	{"redis", 503, CodeServiceUnavailable, "redis: connection pool timeout"},
	{"upstream html", 502, CodeUpstreamError, "unexpected status 502: <html><body>Bad gateway</body></html>"},
	{"upstream json", 400, CodeBadRequest, `jira: status 400: {"errorMessages":["Field 'priority' cannot be set"]}`},
	{"empty", 400, CodeBadRequest, ""},
	{"only id", 404, CodeNotFound, "3f1c2a9e-1b2c-4d5e-8f90-a1b2c3d4e5f6"},
}

func TestSafeMessage_NoLeaks(t *testing.T) {
	for _, s := range leakSamples {
		t.Run(s.name, func(t *testing.T) {
			got, _ := SafeMessage(s.code, s.status, s.msg)
			for name, re := range leakPatterns {
				if re.MatchString(got) {
					t.Errorf("message keeps %s text: %q", name, got)
				}
			}
			if strings.TrimSpace(got) == "" {
				t.Errorf("empty message")
			}
		})
	}
}

func TestSafeMessage_Readable(t *testing.T) {
	cases := map[string]string{
		"Connection test failed: integration 99999999-9999-4999-8999-999999999999 has no credentials": "Connection test failed: integration has no credentials",
		"validation error: name is required": "Name is required",
		"validation error: the issue type chosen for Bug issues (id 3f1c2a9e-1b2c-4d5e-8f90-a1b2c3d4e5f6) does not exist": "The issue type chosen for Bug issues does not exist",
		"asset with id 3f1c2a9e-1b2c-4d5e-8f90-a1b2c3d4e5f6 not found":                                                    "Asset not found",
		"Scan profile name is already used.":                                                                              "Scan profile name is already used.",
	}
	for in, want := range cases {
		if got, _ := SafeMessage(CodeBadRequest, 400, in); got != want {
			t.Errorf("SafeMessage(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestSafeMessage_KeepsUserData(t *testing.T) {
	// An asset's own address or name is what the person typed: not a leak.
	for _, in := range []string{
		"10.0.0.0/8 is outside the organization's scope",
		"api.example.com is excluded by a scope rule",
		"Port must be between 1 and 65535",
	} {
		got, changed := SafeMessage(CodeBadRequest, 400, in)
		if changed || got != in {
			t.Errorf("SafeMessage(%q) = %q, changed=%v; want it unchanged", in, got, changed)
		}
	}
}

func TestSafeMessage_TechnicalUsesCodeDefault(t *testing.T) {
	got, changed := SafeMessage(CodeConflict, 409, `ERROR: duplicate key value violates unique constraint "x" (SQLSTATE 23505)`)
	if !changed || got != registry[CodeConflict].Message {
		t.Fatalf("got %q changed=%v", got, changed)
	}
	got, _ = SafeMessage(Code("SOMETHING_UNREGISTERED"), 404, "pq: no rows")
	if got != registry[CodeNotFound].Message {
		t.Fatalf("unregistered code falls back by status, got %q", got)
	}
}

// TestWriteJSON_ContractNoLeaks writes every sample through the constructors
// handlers use and checks the wire body: the message is clean, the code and
// request id are kept, and details pass through.
func TestWriteJSON_ContractNoLeaks(t *testing.T) {
	ctors := []func(string) *Error{BadRequest, Conflict, Forbidden, Unauthorized, NotFound, InternalServerError,
		ServiceUnavailable, BadGateway, TooManyRequests, func(m string) *Error { return ValidationFailed(m, nil) }}
	for _, s := range leakSamples {
		for _, ctor := range ctors {
			rec := httptest.NewRecorder()
			rec.Header().Set("X-Request-ID", "req-123")
			ctor(s.msg).WriteJSON(rec)
			var body Response
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			for name, re := range leakPatterns {
				if re.MatchString(body.Message) {
					t.Errorf("%s: wire message keeps %s text: %q", s.name, name, body.Message)
				}
			}
			if body.RequestID != "req-123" || body.Code == "" {
				t.Errorf("%s: envelope lost code or request id: %+v", s.name, body)
			}
		}
	}
	// json.Marshal of the error itself (some writers encode *Error).
	b, _ := json.Marshal(BadRequest(leakSamples[0].msg))
	if leakPatterns["uuid"].Match(b) {
		t.Errorf("MarshalJSON keeps the id: %s", b)
	}
}

func TestInternalErrorNeverShowsCause(t *testing.T) {
	rec := httptest.NewRecorder()
	InternalError(errors.New(`pq: relation "secrets" does not exist`)).WriteJSON(rec)
	if strings.Contains(rec.Body.String(), "secrets") || rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestFromCodeAndParams(t *testing.T) {
	e := FromCode(CodeIntegrationNoCredentials).WithParams(Params{
		"name":    "Jira SEC",
		"id":      "3f1c2a9e-1b2c-4d5e-8f90-a1b2c3d4e5f6",
		"cause":   "dial tcp 10.0.0.1:443: i/o timeout",
		"empty":   " ",
		"project": "SEC",
	})
	if e.Status != registry[CodeIntegrationNoCredentials].Status || e.Code != CodeIntegrationNoCredentials {
		t.Fatalf("status/code: %+v", e)
	}
	params := e.Details.(map[string]any)["params"].(map[string]string)
	if params["name"] != "Jira SEC" || params["project"] != "SEC" || len(params) != 2 {
		t.Fatalf("params must keep names and drop ids and technical text: %v", params)
	}
	if got := FromCode(Code("NOT_REGISTERED")); got.Status != 500 || got.Code != CodeInternalError {
		t.Fatalf("unregistered code must be visible as a 500, got %+v", got)
	}
	// Existing details (a list) are kept under data.
	v := ValidationFailed("Validation failed", []ValidationError{{Field: "name", Message: "required"}}).WithParams(Params{"n": "1"})
	if _, ok := v.Details.(map[string]any)["data"]; !ok {
		t.Fatalf("details list lost: %v", v.Details)
	}
}

func TestRegistry_Wording(t *testing.T) {
	codeRe := regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)
	for _, c := range Codes() {
		s, _ := Lookup(c)
		if !codeRe.MatchString(string(c)) {
			t.Errorf("%s: code is not UPPER_SNAKE", c)
		}
		if s.Status < 400 || s.Status > 599 {
			t.Errorf("%s: status %d", c, s.Status)
		}
		if !strings.HasSuffix(s.Message, ".") || strings.Contains(s.Message, "Please") || strings.Contains(s.Message, "—") {
			t.Errorf("%s: message breaks the wording rules: %q", c, s.Message)
		}
		if got, changed := SafeMessage(c, s.Status, s.Message); changed {
			t.Errorf("%s: default message is not safe as is: %q -> %q", c, s.Message, got)
		}
	}
}

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}
