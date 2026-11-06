package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	proxypoolapp "github.com/openctemio/openctem/api/internal/app/proxypool"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ProxyPoolHandler serves an organization's proxy pools for sensor scan
// traffic (/api/v1/proxy-pools; docs/architecture/sensor-proxies.md).
// Tenant from the JWT; every query is tenant-scoped. No response ever
// carries a credential: an endpoint says only whether it has one.
type ProxyPoolHandler struct {
	service *proxypoolapp.Service
	logger  *logger.Logger
}

// NewProxyPoolHandler creates a ProxyPoolHandler.
func NewProxyPoolHandler(svc *proxypoolapp.Service, log *logger.Logger) *ProxyPoolHandler {
	return &ProxyPoolHandler{service: svc, logger: log.With("handler", "proxy_pool")}
}

// Service is the proxy pool service (the sensor routes use it too).
func (h *ProxyPoolHandler) Service() *proxypoolapp.Service { return h.service }

// ProxyEndpointHealthResponse is what the platform knows about an endpoint.
type ProxyEndpointHealthResponse struct {
	State               string     `json:"state"`
	Score               float64    `json:"score"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	OKTotal             int64      `json:"ok_total"`
	FailTotal           int64      `json:"fail_total"`
	HandshakeMsP95      *int       `json:"handshake_ms_p95"`
	LastError           string     `json:"last_error"`
	LastOKAt            *time.Time `json:"last_ok_at"`
	LastFailureAt       *time.Time `json:"last_failure_at"`
	QuarantinedUntil    *time.Time `json:"quarantined_until"`
}

// ProxyEndpointResponse is one endpoint of a pool, without credentials.
type ProxyEndpointResponse struct {
	ID                   string                      `json:"id"`
	Scheme               string                      `json:"scheme"`
	Host                 string                      `json:"host"`
	Port                 int                         `json:"port"`
	Label                string                      `json:"label"`
	Priority             int                         `json:"priority"`
	Enabled              bool                        `json:"enabled"`
	HasCredentials       bool                        `json:"has_credentials"`
	CredentialsUpdatedAt *time.Time                  `json:"credentials_updated_at"`
	Health               ProxyEndpointHealthResponse `json:"health"`
}

// ProxyPoolResponse is a proxy pool.
type ProxyPoolResponse struct {
	ID              string                  `json:"id"`
	Name            string                  `json:"name"`
	Description     string                  `json:"description"`
	Enabled         bool                    `json:"enabled"`
	IsDefault       bool                    `json:"is_default"`
	Strategy        string                  `json:"strategy"`
	Revision        int                     `json:"revision"`
	AssignedSensors int                     `json:"assigned_sensors"`
	EndpointsText   string                  `json:"endpoints_text"`
	Endpoints       []ProxyEndpointResponse `json:"endpoints"`
	CreatedAt       time.Time               `json:"created_at"`
	UpdatedAt       time.Time               `json:"updated_at"`
}

// ProxyPoolListResponse is the tenant's pools.
type ProxyPoolListResponse struct {
	Items []ProxyPoolResponse `json:"items"`
}

// CreateProxyPoolRequest creates a pool.
type CreateProxyPoolRequest struct {
	Name          string  `json:"name"`
	Description   string  `json:"description"`
	Strategy      string  `json:"strategy"`
	Enabled       *bool   `json:"enabled"`
	IsDefault     bool    `json:"is_default"`
	EndpointsText *string `json:"endpoints_text"`
}

// UpdateProxyPoolRequest changes a pool; omitted fields are unchanged.
type UpdateProxyPoolRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Strategy    *string `json:"strategy"`
	Enabled     *bool   `json:"enabled"`
	IsDefault   *bool   `json:"is_default"`
}

// ReplaceProxyEndpointsRequest is a pasted endpoint list.
type ReplaceProxyEndpointsRequest struct {
	Text string `json:"text"`
}

// UpdateProxyEndpointRequest enables, disables or resets an endpoint.
type UpdateProxyEndpointRequest struct {
	Enabled     *bool `json:"enabled"`
	ResetHealth bool  `json:"reset_health"`
}

// ProxyAssignmentResponse is a sensor's network path.
type ProxyAssignmentResponse struct {
	SensorID string  `json:"sensor_id"`
	Mode     string  `json:"mode"`
	PoolID   *string `json:"pool_id"`
}

// ProxyAssignmentListResponse is every sensor that does not inherit.
type ProxyAssignmentListResponse struct {
	Items []ProxyAssignmentResponse `json:"items"`
}

// SetProxyAssignmentRequest sets a sensor's network path.
type SetProxyAssignmentRequest struct {
	Mode   string `json:"mode"`
	PoolID string `json:"pool_id"`
}

func toProxyPoolResponse(p *proxypool.Pool) ProxyPoolResponse {
	out := ProxyPoolResponse{ID: p.ID.String(), Name: p.Name, Description: p.Description, Enabled: p.Enabled,
		IsDefault: p.IsDefault, Strategy: p.Strategy, Revision: p.Revision, AssignedSensors: p.AssignedSensors,
		EndpointsText: proxypool.RenderList(p.Endpoints), Endpoints: make([]ProxyEndpointResponse, 0, len(p.Endpoints)),
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
	for _, e := range p.Endpoints {
		h := e.Health
		out.Endpoints = append(out.Endpoints, ProxyEndpointResponse{ID: e.ID.String(), Scheme: e.Scheme, Host: e.Host,
			Port: e.Port, Label: e.Label, Priority: e.Priority, Enabled: e.Enabled, HasCredentials: e.HasCredentials(),
			CredentialsUpdatedAt: e.CredentialsUpdatedAt,
			Health: ProxyEndpointHealthResponse{State: h.State, Score: h.Score, ConsecutiveFailures: h.ConsecutiveFailures,
				OKTotal: h.OKTotal, FailTotal: h.FailTotal, HandshakeMsP95: h.HandshakeMsP95, LastError: h.LastError,
				LastOKAt: h.LastOKAt, LastFailureAt: h.LastFailureAt, QuarantinedUntil: h.QuarantinedUntil}})
	}
	return out
}

// List handles GET /api/v1/proxy-pools
// @Summary      List proxy pools
// @Description  The organization's proxy pools for sensor scan traffic, with their endpoints and health. Credentials are never returned.
// @Tags         Proxy Pools
// @Produce      json
// @Success      200  {object}  ProxyPoolListResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /proxy-pools [get]
func (h *ProxyPoolHandler) List(w http.ResponseWriter, r *http.Request) {
	actx := buildScanZoneAuditContext(r)
	pools, err := h.service.ListPools(r.Context(), actx.TenantID)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := ProxyPoolListResponse{Items: make([]ProxyPoolResponse, 0, len(pools))}
	for _, p := range pools {
		out.Items = append(out.Items, toProxyPoolResponse(p))
	}
	writeScanZoneJSON(w, http.StatusOK, out)
}

// Get handles GET /api/v1/proxy-pools/{id}
// @Summary      Get a proxy pool
// @Tags         Proxy Pools
// @Produce      json
// @Param        id   path      string  true  "Proxy pool ID"
// @Success      200  {object}  ProxyPoolResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /proxy-pools/{id} [get]
func (h *ProxyPoolHandler) Get(w http.ResponseWriter, r *http.Request) {
	actx := buildScanZoneAuditContext(r)
	p, err := h.service.GetPool(r.Context(), actx.TenantID, chi.URLParam(r, "id"))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toProxyPoolResponse(p))
}

// Create handles POST /api/v1/proxy-pools
// @Summary      Create a proxy pool
// @Description  endpoints_text is a pasted list, one scheme://[user:pass@]host:port[#label] per line. Credentials are stored encrypted and never returned.
// @Tags         Proxy Pools
// @Accept       json
// @Produce      json
// @Param        body  body      CreateProxyPoolRequest  true  "Pool"
// @Success      201   {object}  ProxyPoolResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /proxy-pools [post]
func (h *ProxyPoolHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateProxyPoolRequest
	if !decodeProxyPoolBody(w, r, &req) {
		return
	}
	actx := buildScanZoneAuditContext(r)
	p, err := h.service.CreatePool(r.Context(), proxypoolapp.CreatePoolInput{TenantID: actx.TenantID, Name: req.Name,
		Description: req.Description, Strategy: req.Strategy, Enabled: req.Enabled, IsDefault: req.IsDefault,
		EndpointsText: req.EndpointsText}, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusCreated, toProxyPoolResponse(p))
}

// Update handles PATCH /api/v1/proxy-pools/{id}
// @Summary      Update a proxy pool
// @Tags         Proxy Pools
// @Accept       json
// @Produce      json
// @Param        id    path      string                  true  "Proxy pool ID"
// @Param        body  body      UpdateProxyPoolRequest  true  "Changes"
// @Success      200   {object}  ProxyPoolResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /proxy-pools/{id} [patch]
func (h *ProxyPoolHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req UpdateProxyPoolRequest
	if !decodeProxyPoolBody(w, r, &req) {
		return
	}
	actx := buildScanZoneAuditContext(r)
	p, err := h.service.UpdatePool(r.Context(), proxypoolapp.UpdatePoolInput{TenantID: actx.TenantID, PoolID: chi.URLParam(r, "id"),
		Name: req.Name, Description: req.Description, Strategy: req.Strategy, Enabled: req.Enabled, IsDefault: req.IsDefault}, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toProxyPoolResponse(p))
}

// Delete handles DELETE /api/v1/proxy-pools/{id}
// @Summary      Delete a proxy pool
// @Description  Refused with PROXY_POOL_IN_USE while a sensor uses the pool.
// @Tags         Proxy Pools
// @Param        id   path  string  true  "Proxy pool ID"
// @Success      204
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /proxy-pools/{id} [delete]
func (h *ProxyPoolHandler) Delete(w http.ResponseWriter, r *http.Request) {
	actx := buildScanZoneAuditContext(r)
	if err := h.service.DeletePool(r.Context(), actx.TenantID, chi.URLParam(r, "id"), actx); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ReplaceEndpoints handles PUT /api/v1/proxy-pools/{id}/endpoints
// @Summary      Replace a proxy pool's endpoints
// @Description  A pasted list, one per line; line order is priority. A line whose user information is •••• keeps the stored credentials of the same endpoint.
// @Tags         Proxy Pools
// @Accept       json
// @Produce      json
// @Param        id    path      string                        true  "Proxy pool ID"
// @Param        body  body      ReplaceProxyEndpointsRequest  true  "Endpoint list"
// @Success      200   {object}  ProxyPoolResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /proxy-pools/{id}/endpoints [put]
func (h *ProxyPoolHandler) ReplaceEndpoints(w http.ResponseWriter, r *http.Request) {
	var req ReplaceProxyEndpointsRequest
	if !decodeProxyPoolBody(w, r, &req) {
		return
	}
	actx := buildScanZoneAuditContext(r)
	p, err := h.service.ReplaceEndpoints(r.Context(), actx.TenantID, chi.URLParam(r, "id"), req.Text, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toProxyPoolResponse(p))
}

// UpdateEndpoint handles PATCH /api/v1/proxy-pools/{id}/endpoints/{endpoint_id}
// @Summary      Enable, disable or reset a proxy endpoint
// @Description  reset_health puts a quarantined endpoint back in probation at once.
// @Tags         Proxy Pools
// @Accept       json
// @Produce      json
// @Param        id          path      string                      true  "Proxy pool ID"
// @Param        endpoint_id path      string                      true  "Endpoint ID"
// @Param        body        body      UpdateProxyEndpointRequest  true  "Changes"
// @Success      200         {object}  ProxyPoolResponse
// @Failure      400         {object}  apierror.Error
// @Failure      401         {object}  apierror.Error
// @Failure      403         {object}  apierror.Error
// @Failure      404         {object}  apierror.Error
// @Security     BearerAuth
// @Router       /proxy-pools/{id}/endpoints/{endpoint_id} [patch]
func (h *ProxyPoolHandler) UpdateEndpoint(w http.ResponseWriter, r *http.Request) {
	var req UpdateProxyEndpointRequest
	if !decodeProxyPoolBody(w, r, &req) {
		return
	}
	actx := buildScanZoneAuditContext(r)
	p, err := h.service.UpdateEndpoint(r.Context(), proxypoolapp.UpdateEndpointInput{TenantID: actx.TenantID,
		PoolID: chi.URLParam(r, "id"), EndpointID: chi.URLParam(r, "endpoint_id"), Enabled: req.Enabled,
		ResetHealth: req.ResetHealth}, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toProxyPoolResponse(p))
}

// ListAssignments handles GET /api/v1/proxy-pools/assignments
// @Summary      List sensor network paths
// @Description  Every sensor that does not inherit the organization default: Direct, or a pool.
// @Tags         Proxy Pools
// @Produce      json
// @Success      200  {object}  ProxyAssignmentListResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /proxy-pools/assignments [get]
func (h *ProxyPoolHandler) ListAssignments(w http.ResponseWriter, r *http.Request) {
	actx := buildScanZoneAuditContext(r)
	items, err := h.service.ListAssignments(r.Context(), actx.TenantID)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := ProxyAssignmentListResponse{Items: make([]ProxyAssignmentResponse, 0, len(items))}
	for _, a := range items {
		item := ProxyAssignmentResponse{SensorID: a.SensorID.String(), Mode: a.Mode}
		if a.PoolID != nil {
			v := a.PoolID.String()
			item.PoolID = &v
		}
		out.Items = append(out.Items, item)
	}
	writeScanZoneJSON(w, http.StatusOK, out)
}

// SetAssignment handles PUT /api/v1/proxy-pools/assignments/{sensor_id}
// @Summary      Set a sensor's network path
// @Description  inherit (the organization default pool, public targets only), direct, or pool (a pool of the organization, all targets). Shared sensors cannot be assigned.
// @Tags         Proxy Pools
// @Accept       json
// @Produce      json
// @Param        sensor_id path      string                     true  "Sensor ID"
// @Param        body      body      SetProxyAssignmentRequest  true  "Network path"
// @Success      200       {object}  ProxyAssignmentResponse
// @Failure      400       {object}  apierror.Error
// @Failure      401       {object}  apierror.Error
// @Failure      403       {object}  apierror.Error
// @Failure      404       {object}  apierror.Error
// @Security     BearerAuth
// @Router       /proxy-pools/assignments/{sensor_id} [put]
func (h *ProxyPoolHandler) SetAssignment(w http.ResponseWriter, r *http.Request) {
	var req SetProxyAssignmentRequest
	if !decodeProxyPoolBody(w, r, &req) {
		return
	}
	actx := buildScanZoneAuditContext(r)
	sensorID := chi.URLParam(r, "sensor_id")
	if err := h.service.AssignSensor(r.Context(), actx.TenantID, sensorID, req.Mode, req.PoolID, actx); err != nil {
		h.handleError(w, err)
		return
	}
	out := ProxyAssignmentResponse{SensorID: sensorID, Mode: req.Mode}
	if req.Mode == proxypool.ModePool {
		out.PoolID = &req.PoolID
	}
	writeScanZoneJSON(w, http.StatusOK, out)
}

// maxProxyPoolBody bounds a request body (a pasted list is at most 64 KiB).
const maxProxyPoolBody = proxypool.MaxListBytes + 4096

func decodeProxyPoolBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProxyPoolBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

func (h *ProxyPoolHandler) handleError(w http.ResponseWriter, err error) {
	var le *proxypool.ListError
	var de *shared.DomainError
	switch {
	case errors.As(err, &le):
		apierror.New(http.StatusBadRequest, apierror.Code(le.Code()), le.Error()).WriteJSON(w)
	case errors.Is(err, proxypoolapp.ErrTestRateLimited):
		apierror.TooManyRequests("A proxy pool can be tested once a minute").WriteJSON(w)
	case errors.Is(err, proxypool.ErrSensorNotFound):
		apierror.NotFound("Sensor").WriteJSON(w)
	case errors.Is(err, proxypool.ErrEndpointNotFound):
		apierror.NotFound("Proxy endpoint").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Proxy pool").WriteJSON(w)
	case errors.As(err, &de) && (errors.Is(err, shared.ErrAlreadyExists) || errors.Is(err, shared.ErrConflict)):
		apierror.New(http.StatusConflict, apierror.Code(de.Code), de.Message).WriteJSON(w)
	case errors.As(err, &de) && errors.Is(err, shared.ErrValidation):
		apierror.New(http.StatusBadRequest, apierror.Code(de.Code), de.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(cleanErrorMessage(err, "Invalid proxy pool")).WriteJSON(w)
	default:
		h.logger.Error("proxy pool service error", "error", sanitizeLogField(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
	}
}

// Scanner addresses (docs/architecture/sensor-proxies.md, "Scanner
// addresses"): only addresses the platform observed itself; never a proxy
// credential, never an endpoint's host or port.

// ScannerAddressResponse is one address the organization's scans leave from.
type ScannerAddressResponse struct {
	// Address is an IP address, or a CIDR for a published platform range.
	Address string `json:"address"`
	// CIDR is the address as a prefix (/32 or /128 for one address).
	CIDR string `json:"cidr"`
	// Kind is proxy_exit (a proxy endpoint's exit as the platform's echo saw
	// it), sensor (the address the platform saw one of your sensors connect
	// from) or platform (the published egress of shared sensors).
	Kind          string     `json:"kind" enums:"proxy_exit,sensor,platform"`
	Private       bool       `json:"private"`
	PoolID        string     `json:"pool_id,omitempty"`
	PoolName      string     `json:"pool_name,omitempty"`
	EndpointID    string     `json:"endpoint_id,omitempty"`
	EndpointLabel string     `json:"endpoint_label,omitempty"`
	SensorID      string     `json:"sensor_id,omitempty"`
	SensorName    string     `json:"sensor_name,omitempty"`
	Region        string     `json:"region,omitempty"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
}

// ScannerAddressesResponse is the organization's scanner addresses and the
// unique prefixes to allowlist.
type ScannerAddressesResponse struct {
	Items []ScannerAddressResponse `json:"items"`
	CIDRs []string                 `json:"cidrs"`
}

// ScannerAddresses handles GET /api/v1/proxy-pools/scanner-addresses
// @Summary      Scanner addresses
// @Description  The addresses the organization's scans leave from, to allowlist at a WAF or edge protection: each proxy endpoint's exit address as the platform's own test echo saw it (run a proxy test to learn it), the addresses the platform saw your sensors connect from (last 30 days), and the published egress of shared sensors when the organization may use them. A value reported only by a sensor is never listed. No credentials.
// @Tags         Proxy Pools
// @Produce      json
// @Success      200  {object}  ScannerAddressesResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /proxy-pools/scanner-addresses [get]
func (h *ProxyPoolHandler) ScannerAddresses(w http.ResponseWriter, r *http.Request) {
	actx := buildScanZoneAuditContext(r)
	v, err := h.service.ScannerAddresses(r.Context(), actx.TenantID)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := ScannerAddressesResponse{Items: make([]ScannerAddressResponse, 0, len(v.Items)), CIDRs: v.CIDRs}
	for _, a := range v.Items {
		out.Items = append(out.Items, ScannerAddressResponse{Address: a.Address, CIDR: a.CIDR, Kind: a.Kind, Private: a.Private,
			PoolID: a.PoolID, PoolName: a.PoolName, EndpointID: a.EndpointID, EndpointLabel: a.EndpointLabel,
			SensorID: a.SensorID, SensorName: a.SensorName, Region: a.Region, LastSeenAt: a.LastSeenAt})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeScanZoneJSON(w, http.StatusOK, out)
}
