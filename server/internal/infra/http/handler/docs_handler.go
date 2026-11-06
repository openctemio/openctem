package handler

import (
	"encoding/json"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/openctemio/openctem/api/pkg/brand"
)

// DocsHandler handles API documentation endpoints
type DocsHandler struct {
	specPath string
}

// NewDocsHandler creates a new DocsHandler
// specPath is the path to the OpenAPI spec file (e.g., "api/openapi/openapi.yaml")
func NewDocsHandler(specPath string) *DocsHandler {
	return &DocsHandler{
		specPath: specPath,
	}
}

// ServeOpenAPISpec serves the OpenAPI specification file
func (h *DocsHandler) ServeOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	content, err := os.ReadFile(h.specPath)
	if err != nil {
		// Try relative to working directory
		wd, _ := os.Getwd()
		altPath := filepath.Join(wd, h.specPath)
		content, err = os.ReadFile(altPath)
		if err != nil {
			http.Error(w, "OpenAPI spec not found", http.StatusNotFound)
			return
		}
	}

	// Determine current host (scheme detection available but not currently used)
	_ = schemeHTTP // Constants available for future scheme replacement
	host := r.Host

	// Replace host and schemes in the content
	// This allows "Try it out" to work regardless of where the API is hosted
	yamlStr := string(content)

	// Simple string replacement for standard swag output
	// Note: a more robust approach would be parsing YAML, but that adds overhead/deps.
	// We assume strictly generated format here.

	// Replace host (assuming "host: localhost:8080" format)
	// We use regex-like replacement by finding line start
	lines := strings.Split(yamlStr, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "host: ") {
			lines[i] = "host: " + host
		}
		// Note: schemes handling is not implemented yet - the swagger client
		// infers the scheme from the current access method.
	}

	// Reassemble
	modifiedContent := strings.Join(lines, "\n")

	// Also ensure scheme matches current access method if not present?
	// If swagger.yaml has 'schemes: [http]' and we access via https, 'Try it out' might fail.
	// But valid solution for now is updating Host.

	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-cache") // Disable cache so it updates with host
	w.Write([]byte(modifiedContent))
}

// Spec paths the documentation pages load. The public pair exists outside
// production only; the console pair is for platform administrators.
const (
	PublicSpecPath  = "/openapi.yaml"
	ConsoleSpecPath = "/api/v1/admin/openapi.yaml"
)

// scalarScript is the pinned API reference bundle and its subresource
// integrity hash: the browser runs exactly these bytes or nothing, so a
// changed package on the CDN cannot run code on the API origin.
const (
	scalarScriptURL       = "https://cdn.jsdelivr.net/npm/@scalar/api-reference@1.73.1/dist/browser/standalone.js"
	scalarScriptIntegrity = "sha256-YsNKDdo4lFhkAR669uf6eBKjMkKRINGJIrNNAcT3zMg="
)

// ServeDocsUI serves the API reference page that loads the public spec.
func (h *DocsHandler) ServeDocsUI(w http.ResponseWriter, r *http.Request) {
	serveDocsPage(w, PublicSpecPath, "public, max-age=3600")
}

// ServeConsoleDocsUI serves the API reference page for platform
// administrators; it loads the spec through the console route.
func (h *DocsHandler) ServeConsoleDocsUI(w http.ResponseWriter, r *http.Request) {
	serveDocsPage(w, ConsoleSpecPath, "no-store")
}

// serveDocsPage writes the reference page. The spec URL is a fixed
// same-origin path (never built from the Host header), and the page carries
// its own CSP: the pinned script only, requests to this origin only.
func serveDocsPage(w http.ResponseWriter, specPath, cacheControl string) {
	// The brand name is escaped for HTML text, and JSON-encoded then
	// HTML-escaped where it sits inside the configuration attribute.
	name := brand.Name()
	nameJSON, _ := json.Marshal(name + " API")
	page := strings.NewReplacer(
		"{{SPEC_URL}}", specPath,
		"{{PRODUCT}}", html.EscapeString(name),
		`"{{PRODUCT_API_JSON}}"`, html.EscapeString(string(nameJSON)),
	).Replace(scalarHTML)
	page = strings.ReplaceAll(page, "{{SCRIPT_URL}}", scalarScriptURL)
	page = strings.ReplaceAll(page, "{{SCRIPT_INTEGRITY}}", scalarScriptIntegrity)

	csp := "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
		"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; " +
		"font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; " +
		"img-src 'self' data: https:; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'"

	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Content-Type", "text/page; charset=utf-8")
	w.Header().Set("Cache-Control", cacheControl)
	_, _ = w.Write([]byte(page))
}

const scalarHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{PRODUCT}} API Documentation</title>
  <meta name="description" content="{{PRODUCT}} API Documentation">
  <style>
    body {
      margin: 0;
      padding: 0;
    }
  </style>
</head>
<body>
  <script
    id="api-reference"
    data-url="{{SPEC_URL}}"
    data-configuration='{
      "theme": "kepler",
      "layout": "modern",
      "darkMode": true,
      "hiddenClients": ["unirest"],
      "defaultHttpClient": {
        "targetKey": "javascript",
        "clientKey": "fetch"
      },
      "authentication": {
        "preferredSecurityScheme": "bearerAuth"
      },
      "spec": {
        "url": "{{SPEC_URL}}"
      },
      "metaData": {
        "title": "{{PRODUCT_API_JSON}}",
        "description": "Security Platform API"
      }
    }'
  ></script>
  <script src="{{SCRIPT_URL}}" integrity="{{SCRIPT_INTEGRITY}}" crossorigin="anonymous"></script>
</body>
</html>`
