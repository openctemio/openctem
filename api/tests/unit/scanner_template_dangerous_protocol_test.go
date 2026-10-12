package unit

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A tenant admin cannot upload (or update to) a nuclei template that uses a
// protocol which runs code on the sensor, reads its files or drives a
// browser, nor a self-contained one: the API refuses it with a validation
// error naming the protocol, and nothing is stored.
func TestScannerTemplateService_RejectsDangerousNucleiProtocols(t *testing.T) {
	head := "id: pwn\ninfo:\n  name: pwn\n  author: x\n  severity: info\n"
	cases := map[string]struct {
		body, want string
	}{
		"code":           {head + "code:\n  - engine: [sh]\n    source: id\n", `the "code" protocol runs code on the scanner`},
		"code (json)":    {`{"id":"pwn","info":{"name":"x","author":"x","severity":"info"},"Code":[{"engine":["sh"],"source":"id"}]}`, `the "code" protocol`},
		"javascript":     {head + "javascript:\n  - code: '1'\n", `the "javascript" protocol runs code on the scanner`},
		"headless":       {head + "headless:\n  - steps:\n      - action: navigate\n", `the "headless" protocol drives a browser`},
		"file":           {head + "file:\n  - extensions: [all]\n    matchers:\n      - type: word\n        words: [root]\n", `the "file" protocol reads files on the scanner`},
		"self-contained": {head + "self-contained: true\nhttp:\n  - raw:\n      - GET / HTTP/1.1\n", "self-contained templates are not allowed"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			repo := newScannerTemplateMockRepository()
			svc := newTestScannerTemplateService(repo)
			_, err := svc.CreateTemplate(context.Background(), app.CreateScannerTemplateInput{
				TenantID:     shared.NewID().String(),
				Name:         "pwn",
				TemplateType: "nuclei",
				Content:      base64.StdEncoding.EncodeToString([]byte(c.body)),
			})
			if err == nil || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want a validation error", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not say %q", err, c.want)
			}
			if len(repo.templates) != 0 {
				t.Error("a refused template was stored")
			}
		})
	}

	// Updating an accepted template to a forbidden protocol is refused too.
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)
	tenant := shared.NewID().String()
	tmpl, err := svc.CreateTemplate(context.Background(), app.CreateScannerTemplateInput{
		TenantID: tenant, Name: "ok", TemplateType: "nuclei", Content: validNucleiYAML(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.UpdateTemplate(context.Background(), app.UpdateScannerTemplateInput{
		TenantID: tenant, TemplateID: tmpl.ID.String(),
		Content: base64.StdEncoding.EncodeToString([]byte(cases["file"].body)),
	})
	if err == nil || !strings.Contains(err.Error(), `"file" protocol`) {
		t.Fatalf("update to a file-protocol template: %v", err)
	}
}
