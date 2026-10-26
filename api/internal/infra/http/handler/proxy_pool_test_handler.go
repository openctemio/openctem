package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	proxypoolapp "github.com/openctemio/openctem/api/internal/app/proxypool"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
)

// The Test button of a proxy pool (docs/architecture/sensor-proxies.md):
// the platform never connects to a proxy; it asks up to three of the
// organization's online sensors to test each endpoint and reads their
// results back. Tenant from the JWT; the pool and every sensor and command
// are looked up inside it, so another organization's ids are not found.

// ProxyPoolTestRequest asks sensors to test a pool.
type ProxyPoolTestRequest struct {
	// SensorIDs are the sensors that run the test (1 to 3): sensors of the
	// organization that are online and report proxy.test@1.
	SensorIDs []string `json:"sensor_ids"`
}

// ProxyPoolTestItem is one test that was queued.
type ProxyPoolTestItem struct {
	SensorID   string `json:"sensor_id"`
	SensorName string `json:"sensor_name"`
	CommandID  string `json:"command_id"`
}

// ProxyPoolTestResponse lists the queued tests; read them with
// GET /proxy-pools/{id}/tests?command_ids=...
type ProxyPoolTestResponse struct {
	Items []ProxyPoolTestItem `json:"items"`
}

// ProxyPoolTestEndpointResult is one endpoint's result of a test.
type ProxyPoolTestEndpointResult struct {
	EndpointID string `json:"endpoint_id"`
	// Address is scheme://host:port of the endpoint, never credentials.
	Address string `json:"address"`
	OK      bool   `json:"ok"`
	// Class is why a test failed: proxy_down, proxy_auth,
	// target_unreachable, target_refused or echo_failed.
	Class       string `json:"class,omitempty"`
	HandshakeMs int    `json:"handshake_ms"`
	// ExitIP is the address the platform's echo saw through the proxy.
	ExitIP string `json:"exit_ip,omitempty"`
	// Families are the IP families the proxy carried: v4, v6.
	Families []string `json:"families,omitempty"`
	// PortRestricted is true for a proxy that carries 443 and refuses
	// other ports; absent when not decided.
	PortRestricted *bool  `json:"port_restricted,omitempty"`
	Error          string `json:"error,omitempty"`
}

// ProxyPoolTestOutcome is one sensor's test.
type ProxyPoolTestOutcome struct {
	CommandID  string `json:"command_id"`
	SensorID   string `json:"sensor_id"`
	SensorName string `json:"sensor_name"`
	// Status is pending, running, completed, failed, canceled or expired.
	Status     string                        `json:"status"`
	Error      string                        `json:"error,omitempty"`
	FinishedAt *time.Time                    `json:"finished_at,omitempty"`
	Results    []ProxyPoolTestEndpointResult `json:"results"`
}

// ProxyPoolTestResultsResponse is the tests asked for.
type ProxyPoolTestResultsResponse struct {
	Items []ProxyPoolTestOutcome `json:"items"`
}

// Test handles POST /api/v1/proxy-pools/{id}/test
// @Summary      Test a proxy pool
// @Description  Asks 1 to 3 online sensors of the organization to test every endpoint of the pool: handshake time, exit address through the platform's echo, IPv4 and IPv6, and whether the proxy only allows port 443. The platform never connects to a proxy. One test per pool per minute. A shared sensor, one that is not online and one that does not report proxy.test@1 are refused. The pool may be disabled and unassigned (test before enabling).
// @Tags         Proxy Pools
// @Accept       json
// @Produce      json
// @Param        id    path      string                 true  "Proxy pool ID"
// @Param        body  body      ProxyPoolTestRequest   true  "Sensors"
// @Success      202   {object}  ProxyPoolTestResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      429   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /proxy-pools/{id}/test [post]
func (h *ProxyPoolHandler) Test(w http.ResponseWriter, r *http.Request) {
	var req ProxyPoolTestRequest
	if !decodeProxyPoolBody(w, r, &req) {
		return
	}
	actx := buildScanZoneAuditContext(r)
	handles, err := h.service.RequestTest(r.Context(), proxypoolapp.TestRequest{TenantID: actx.TenantID,
		PoolID: chi.URLParam(r, "id"), SensorIDs: req.SensorIDs}, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := ProxyPoolTestResponse{Items: make([]ProxyPoolTestItem, 0, len(handles))}
	for _, t := range handles {
		out.Items = append(out.Items, ProxyPoolTestItem{SensorID: t.SensorID, SensorName: t.SensorName, CommandID: t.CommandID})
	}
	writeScanZoneJSON(w, http.StatusAccepted, out)
}

// TestResults handles GET /api/v1/proxy-pools/{id}/tests
// @Summary      Read the results of proxy pool tests
// @Description  The tests started by POST /proxy-pools/{id}/test, by command id (1 to 3, comma separated). Poll until every status is completed, failed, canceled or expired. A command of another pool or organization is not found.
// @Tags         Proxy Pools
// @Produce      json
// @Param        id           path   string  true  "Proxy pool ID"
// @Param        command_ids  query  string  true  "Command ids from the test request, comma separated"
// @Success      200  {object}  ProxyPoolTestResultsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /proxy-pools/{id}/tests [get]
func (h *ProxyPoolHandler) TestResults(w http.ResponseWriter, r *http.Request) {
	actx := buildScanZoneAuditContext(r)
	ids := strings.Split(r.URL.Query().Get("command_ids"), ",")
	outcomes, err := h.service.TestResults(r.Context(), actx.TenantID, chi.URLParam(r, "id"), ids)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := ProxyPoolTestResultsResponse{Items: make([]ProxyPoolTestOutcome, 0, len(outcomes))}
	for _, o := range outcomes {
		item := ProxyPoolTestOutcome{CommandID: o.CommandID, SensorID: o.SensorID, SensorName: o.SensorName, Status: o.Status,
			Error: o.Error, FinishedAt: o.FinishedAt, Results: make([]ProxyPoolTestEndpointResult, 0, len(o.Results))}
		for _, e := range o.Results {
			item.Results = append(item.Results, ProxyPoolTestEndpointResult{EndpointID: e.EndpointID, Address: e.Address, OK: e.OK,
				Class: e.Class, HandshakeMs: e.HandshakeMs, ExitIP: e.ExitIP, Families: e.Families,
				PortRestricted: e.PortRestricted, Error: e.Error})
		}
		out.Items = append(out.Items, item)
	}
	writeScanZoneJSON(w, http.StatusOK, out)
}

// ProxyTestEchoHandler serves the platform's echo for proxy tests: the page
// a sensor requests through a proxy, which answers the address the request
// came from. There is no session and no sensor key on it (the request
// leaves through a proxy the organization chose): the URL carries the token
// of one live proxy_test command, and the page answers not found for
// anything else, so it tells nothing to a caller without a token.
type ProxyTestEchoHandler struct {
	service *proxypoolapp.Service
}

// NewProxyTestEchoHandler creates a ProxyTestEchoHandler.
func NewProxyTestEchoHandler(svc *proxypoolapp.Service) *ProxyTestEchoHandler {
	return &ProxyTestEchoHandler{service: svc}
}

// ProxyTestEchoResponse is the echo's answer.
type ProxyTestEchoResponse struct {
	Address string `json:"address"`
}

// Echo handles GET /api/v1/proxy-test-echoes/{nonce}
// @Summary      Proxy test echo
// @Description  Answers the address the request came from, for the token of a live proxy test command. Called by sensors through the proxy under test; every other request is not found.
// @Tags         Proxy Pools
// @Produce      json
// @Param        nonce       path      string  true  "Token of the test"
// @Success      200         {object}  ProxyTestEchoResponse
// @Failure      404         {object}  apierror.Error
// @Router       /proxy-test-echoes/{nonce} [get]
func (h *ProxyTestEchoHandler) Echo(w http.ResponseWriter, r *http.Request) {
	tenantID, commandID, nonce, ok := proxypoolapp.SplitTestEchoToken(chi.URLParam(r, "nonce"))
	if !ok || !h.service.VerifyTestEcho(r.Context(), tenantID, commandID, nonce) {
		apierror.NotFound("Page").WriteJSON(w)
		return
	}
	// The address as the platform's trusted edge sees it (never a raw
	// forwarded header).
	addr := middleware.RequestClientIP(r)
	if addr == "" {
		apierror.NotFound("Page").WriteJSON(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeScanZoneJSON(w, http.StatusOK, ProxyTestEchoResponse{Address: addr})
}
