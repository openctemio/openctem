package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// ResolvedPortItem is one open port of an address the name resolves to.
type ResolvedPortItem struct {
	AddressID string     `json:"address_id"`
	Address   string     `json:"address"`
	PortID    string     `json:"port_id"`
	Port      int        `json:"port"`
	Transport string     `json:"transport,omitempty"`
	Service   string     `json:"service,omitempty"`
	Product   string     `json:"product,omitempty"`
	Version   string     `json:"version,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
}

// ResolvedPortsResponse lists the open ports of the addresses a name
// resolves to.
type ResolvedPortsResponse struct {
	Items []ResolvedPortItem `json:"items"`
	// HiddenCount counts ports whose address or port asset is outside the
	// caller's data scope (counted, never listed).
	HiddenCount int64 `json:"hidden_count"`
	// Truncated is set when the name has more ports than Items lists.
	Truncated bool `json:"truncated"`
}

// GetResolvedPorts handles GET /api/v1/assets/{id}/resolved-ports
// @Summary      Ports on a name's resolved addresses
// @Description  For a domain or subdomain: the open ports of the addresses it resolves to (name resolves_to address, address exposes open port), by address then port, with the service, product and version a scanner identified and when the port was last seen. At most 200 rows (truncated is set when there are more). Addresses and ports outside the caller's data scope are only counted (hidden_count). Other asset types answer an empty list.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Asset ID"
// @Success      200  {object}  ResolvedPortsResponse
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/resolved-ports [get]
func (h *AssetHandler) GetResolvedPorts(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	res, err := h.service.GetResolvedPorts(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	out := ResolvedPortsResponse{Items: make([]ResolvedPortItem, 0, len(res.Items)),
		HiddenCount: res.HiddenCount, Truncated: res.Truncated}
	for _, it := range res.Items {
		out.Items = append(out.Items, ResolvedPortItem{
			AddressID: it.AddressID.String(), Address: it.Address, PortID: it.PortID.String(), Port: it.Port,
			Transport: it.Transport, Service: it.Service, Product: it.Product, Version: it.Version, LastSeen: it.LastSeen,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
