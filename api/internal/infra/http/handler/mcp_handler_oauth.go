package handler

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
)

// rpcInsufficientScope is the JSON-RPC error of a call refused for a missing
// OAuth scope (implementation-defined server error range).
const rpcInsufficientScope = -32001

// SetResourceMetadataURL sets the Protected Resource Metadata URL named in
// insufficient_scope challenges. Empty disables the challenges.
func (h *MCPHandler) SetResourceMetadataURL(u string) {
	h.resourceMetadata = u
}

// writeScopeChallenge answers a call refused for perm with an OAuth step-up
// challenge when that is what would help: the request carries an MCP access
// token, the user holds perm, and a scope the token lacks covers it. The
// client can then ask the person for that scope (MCP authorization, scope
// challenge handling: 403 with WWW-Authenticate error="insufficient_scope").
// It reports whether it wrote the response; otherwise the caller answers
// with the ordinary permission error, because no new scope would change the
// outcome.
func (h *MCPHandler) writeScopeChallenge(w http.ResponseWriter, r *http.Request, id json.RawMessage, perm string) bool {
	p := middleware.GetMCPPrincipal(r.Context())
	if p == nil || h.resourceMetadata == "" || perm == "" {
		return false
	}
	if !p.HeldAll && !slices.Contains(p.Held, perm) {
		return false
	}
	needed := mcpoauth.ScopesFor(perm)
	if len(needed) == 0 {
		return false
	}
	w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+mcpoauth.Join(needed)+
		`", resource_metadata="`+h.resourceMetadata+`", error_description="this call needs another permission"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(jsonrpcResponse{
		JSONRPC: "2.0", ID: id,
		Error: &jsonrpcError{Code: rpcInsufficientScope, Message: "insufficient scope: " + mcpoauth.Join(needed)},
	})
	return true
}

// oauthAuditMetadata adds the OAuth grant and client of the request to an
// MCP audit event's metadata.
func oauthAuditMetadata(r *http.Request, md map[string]any) {
	p := middleware.GetMCPPrincipal(r.Context())
	if p == nil {
		return
	}
	md["auth_method"] = middleware.AuthProviderMCPOAuth
	md["grant_id"] = p.GrantID
	md["client_id"] = p.ClientID
	md["client_name"] = p.ClientName
}
