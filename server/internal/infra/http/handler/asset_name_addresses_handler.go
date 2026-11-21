package handler

// GET /api/v1/assets/{id}/addresses: the addresses a name resolves to, with
// their history (research/531). An address inside a range a provider
// publishes for infrastructure many organizations share is recorded on the
// name, not as an address asset, so this is where it is read.

import (
	"encoding/json"
	"net/http"
	"time"

	assetapp "github.com/openctemio/openctem/server/internal/app/asset"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
)

// NameAddressSourceItem is one source's record of an address.
type NameAddressSourceItem struct {
	// Kind: scan, import, integration, feed or manual.
	Kind      string     `json:"kind"`
	Name      string     `json:"name"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	RemovedAt *time.Time `json:"removed_at,omitempty"`
}

// NameAddressItem is one address the name resolved to.
type NameAddressItem struct {
	Address string `json:"address"`
	// Provider and Class are set for an address inside a provider's
	// published shared range (class edge, saas_hosting or cloud_shared).
	Provider string `json:"provider,omitempty"`
	Class    string `json:"class,omitempty"`
	// Current: a source still reports it.
	Current   bool                    `json:"current"`
	FirstSeen time.Time               `json:"first_seen"`
	LastSeen  time.Time               `json:"last_seen"`
	RemovedAt *time.Time              `json:"removed_at,omitempty"`
	Sources   []NameAddressSourceItem `json:"sources"`
}

// NameAddressesResponse lists a name's addresses: current first, then by
// provider and address.
type NameAddressesResponse struct {
	Items []NameAddressItem `json:"items"`
	// Truncated counts the addresses left out past the read's limit (2000).
	Truncated int `json:"truncated"`
}

// GetNameAddresses handles GET /api/v1/assets/{id}/addresses
// @Summary      Addresses a name resolves to, with history
// @Description  For a domain or subdomain: every address its DNS answers held, from each source's record (first seen, last seen, removed), current addresses first. An address inside a range a provider publishes for infrastructure many organizations share carries the provider; such addresses are recorded here, not as address assets. At most 2000 addresses (truncated counts the rest). Other asset types answer an empty list.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Asset ID"
// @Success      200  {object}  NameAddressesResponse
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/addresses [get]
func (h *AssetHandler) GetNameAddresses(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	res, err := h.service.GetNameAddresses(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toNameAddressesResponse(res))
}

func toNameAddressesResponse(res *assetapp.NameAddresses) NameAddressesResponse {
	out := NameAddressesResponse{Items: make([]NameAddressItem, 0, len(res.Items)), Truncated: res.Truncated}
	for _, it := range res.Items {
		item := NameAddressItem{Address: it.Address, Provider: it.Provider, Class: it.Class, Current: it.Current,
			FirstSeen: it.FirstSeen, LastSeen: it.LastSeen, RemovedAt: it.RemovedAt,
			Sources: make([]NameAddressSourceItem, 0, len(it.Sources))}
		for _, s := range it.Sources {
			item.Sources = append(item.Sources, NameAddressSourceItem{Kind: s.Kind, Name: s.Name,
				FirstSeen: s.FirstSeen, LastSeen: s.LastSeen, RemovedAt: s.RemovedAt})
		}
		out.Items = append(out.Items, item)
	}
	return out
}
