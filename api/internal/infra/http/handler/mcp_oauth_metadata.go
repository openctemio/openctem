package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/dpop"
)

// MCPResourceMetadataHandler serves the OAuth 2.0 Protected Resource Metadata
// (RFC 9728) of the MCP endpoint. An MCP client reads it to learn which
// authorization server issues tokens for the endpoint and which scopes to ask
// for (RFC-062 §4).
type MCPResourceMetadataHandler struct {
	endpoints mcpoauth.Endpoints
}

// NewMCPResourceMetadataHandler builds the handler for the given endpoints.
func NewMCPResourceMetadataHandler(e mcpoauth.Endpoints) *MCPResourceMetadataHandler {
	return &MCPResourceMetadataHandler{endpoints: e}
}

// protectedResourceMetadata is the RFC 9728 §2 document.
type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name"`
	// DPoP (RFC 9449 §5.1): proofs accepted; bound tokens optional unless an
	// organization requires them.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported"`
	DPoPBoundAccessTokensRequired bool     `json:"dpop_bound_access_tokens_required"`
}

// Serve answers GET on both well-known locations: the one with the MCP path
// inserted and the root fallback. The document is public, static and holds
// no tenant data, so any origin may read it (browser-based MCP clients).
//
// RFC 9728 §3.3: the resource in the document must equal the resource the
// client derived the metadata URL from; both locations describe the same
// single resource.
func (h *MCPResourceMetadataHandler) Serve(w http.ResponseWriter, _ *http.Request) {
	scopes := mcpoauth.ReadScopes()
	names := make([]string, len(scopes))
	for i, s := range scopes {
		names[i] = string(s)
	}
	doc := protectedResourceMetadata{
		Resource:                      h.endpoints.Resource,
		AuthorizationServers:          []string{h.endpoints.Issuer},
		ScopesSupported:               names,
		BearerMethodsSupported:        []string{"header"},
		ResourceName:                  "OpenCTEM",
		DPoPSigningAlgValuesSupported: dpop.Algorithms,
	}
	writePublicMetadata(w, doc)
}

// writePublicMetadata writes a public, cacheable OAuth metadata document.
func writePublicMetadata(w http.ResponseWriter, doc any) {
	hdr := w.Header()
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Cache-Control", "public, max-age=300")
	// Public document: readable from any origin, never with credentials.
	hdr.Set("Access-Control-Allow-Origin", "*")
	hdr.Del("Access-Control-Allow-Credentials")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}
