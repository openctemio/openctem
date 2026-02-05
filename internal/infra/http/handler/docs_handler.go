package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// ServeDocsUI serves the Scalar API documentation UI
func (h *DocsHandler) ServeDocsUI(w http.ResponseWriter, r *http.Request) {
	// Get the base URL for the OpenAPI spec
	scheme := schemeHTTP
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == schemeHTTPS {
		scheme = schemeHTTPS
	}
	host := r.Host
	specURL := scheme + "://" + host + "/openapi.yaml"

	html := strings.ReplaceAll(scalarHTML, "{{SPEC_URL}}", specURL)

	// Set CSP headers to allow Scalar UI to load properly
	// This overrides the restrictive API CSP for the docs page only
	csp := "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
		"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; " +
		"font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; " +
		"img-src 'self' data: https:; " +
		"connect-src 'self' " + scheme + "://" + host + "; " +
		"frame-ancestors 'none'"

	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write([]byte(html))
}

const scalarHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Exploop API Documentation</title>
  <meta name="description" content="Exploop Security Platform API Documentation">
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
        "title": "Exploop API",
        "description": "Security Platform API"
      }
    }'
  ></script>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>`
