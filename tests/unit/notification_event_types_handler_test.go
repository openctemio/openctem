package unit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	integrationdom "github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// GET /me/event-types
//
// integration.AllEventTypes() is the registry the notification outbox routes
// on. Until this endpoint existed it had no HTTP consumer, so every client kept
// a hand-written copy that drifted from it — six event types were registered
// server-side with no way for an operator to switch them on.
//
// These tests assert the endpoint is that consumer: whatever the domain
// registry says, the wire says. They are written against AllEventTypes() rather
// than a literal list so they cannot themselves become a third copy.
// =============================================================================

const eventTypesTestTenantID = "11111111-1111-1111-1111-111111111111"

// newEventTypesRequest builds a request carrying the tenant context the handler
// reads, since the route's middleware chain is not exercised here.
func newEventTypesRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/event-types", nil)
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, eventTypesTestTenantID)
	return req.WithContext(ctx)
}

// newEventTypesHandler wires a BootstrapHandler over a module repo seeded with
// the given enabled top-level modules.
func newEventTypesHandler(t *testing.T, moduleIDs ...string) *handler.BootstrapHandler {
	t.Helper()

	repo := newModuleMockRepo()
	for _, id := range moduleIDs {
		repo.addModule(makeModule(id, id, true, true))
	}
	svc := newTestModuleService(repo)

	return handler.NewBootstrapHandler(nil, nil, svc, nil, logger.NewNop())
}

func decodeEventTypes(t *testing.T, rec *httptest.ResponseRecorder) handler.TenantEventTypesResponse {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /me/event-types: status = %d, want %d (body: %s)",
			rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp handler.TenantEventTypesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rec.Body.String())
	}
	return resp
}

// TestGetTenantEventTypes_ExposesTheSixPreviouslyUndeliverableTypes is the
// regression guard for the drift this endpoint exists to end. Each of these six
// was registered in AllEventTypes() and routed by the outbox, yet no operator
// could enable it because no client could learn it existed.
func TestGetTenantEventTypes_ExposesTheSixPreviouslyUndeliverableTypes(t *testing.T) {
	h := newEventTypesHandler(t, integrationdom.ModuleFindings)

	rec := httptest.NewRecorder()
	h.GetTenantEventTypes(rec, newEventTypesRequest())
	resp := decodeEventTypes(t, rec)

	got := make(map[string]handler.NotificationEventTypeResponse, len(resp.EventTypes))
	for _, et := range resp.EventTypes {
		got[et.Type] = et
	}

	// All six require the findings module, which the tenant above has.
	for _, want := range []string{
		string(integrationdom.EventTypeSLABreach),
		string(integrationdom.EventTypeApprovalRequested),
		string(integrationdom.EventTypeApprovalApproved),
		string(integrationdom.EventTypeApprovalRejected),
		string(integrationdom.EventTypeFindingAssigned),
		string(integrationdom.EventTypeWorkflowNotification),
	} {
		info, ok := got[want]
		if !ok {
			t.Errorf("event type %q is registered in AllEventTypes() but GET /me/event-types "+
				"did not return it — no operator can switch it on", want)
			continue
		}
		// A checkbox with no label or no description is not usable, which is
		// the whole reason the response carries EventTypeInfo rather than
		// bare strings.
		if info.Label == "" {
			t.Errorf("event type %q returned with an empty label", want)
		}
		if info.Description == "" {
			t.Errorf("event type %q returned with an empty description", want)
		}
		if info.Category == "" {
			t.Errorf("event type %q returned with an empty category", want)
		}
	}
}

// TestGetTenantEventTypes_MatchesTheDomainRegistry pins the response to
// AllEventTypes() as a whole, so a type added to the registry later cannot go
// missing from the wire the way these six did.
func TestGetTenantEventTypes_MatchesTheDomainRegistry(t *testing.T) {
	h := newEventTypesHandler(t,
		integrationdom.ModuleAssets,
		integrationdom.ModuleScans,
		integrationdom.ModuleFindings,
	)

	rec := httptest.NewRecorder()
	h.GetTenantEventTypes(rec, newEventTypesRequest())
	resp := decodeEventTypes(t, rec)

	want := integrationdom.AllEventTypes()
	if len(want) == 0 {
		t.Fatal("AllEventTypes() is empty — this test would pass vacuously")
	}
	if len(resp.EventTypes) != len(want) {
		t.Fatalf("a tenant with every module got %d event types, want all %d from AllEventTypes()",
			len(resp.EventTypes), len(want))
	}
	if resp.TotalCount != len(resp.EventTypes) {
		t.Errorf("total_count = %d, want %d", resp.TotalCount, len(resp.EventTypes))
	}

	got := make(map[string]handler.NotificationEventTypeResponse, len(resp.EventTypes))
	for _, et := range resp.EventTypes {
		got[et.Type] = et
	}
	for _, info := range want {
		actual, ok := got[string(info.Type)]
		if !ok {
			t.Errorf("event type %q missing from response", info.Type)
			continue
		}
		if actual.Label != info.Label {
			t.Errorf("event type %q: label = %q, want %q", info.Type, actual.Label, info.Label)
		}
		if actual.Description != info.Description {
			t.Errorf("event type %q: description = %q, want %q", info.Type, actual.Description, info.Description)
		}
		if actual.Category != string(info.Category) {
			t.Errorf("event type %q: category = %q, want %q", info.Type, actual.Category, info.Category)
		}
		if actual.RequiredModule != info.RequiredModule {
			t.Errorf("event type %q: required_module = %q, want %q", info.Type, actual.RequiredModule, info.RequiredModule)
		}
	}
}

// TestGetTenantEventTypes_DefaultEnabledMatchesDomain checks the default flags,
// which are what a client seeds a new channel's form with. enabled_event_types
// is an opt-in whitelist, so getting these wrong means silent non-delivery.
func TestGetTenantEventTypes_DefaultEnabledMatchesDomain(t *testing.T) {
	h := newEventTypesHandler(t,
		integrationdom.ModuleAssets,
		integrationdom.ModuleScans,
		integrationdom.ModuleFindings,
	)

	rec := httptest.NewRecorder()
	h.GetTenantEventTypes(rec, newEventTypesRequest())
	resp := decodeEventTypes(t, rec)

	wantDefaults := make(map[string]bool)
	for _, et := range integrationdom.DefaultEnabledEventTypes() {
		wantDefaults[string(et)] = true
	}
	if len(wantDefaults) == 0 {
		t.Fatal("DefaultEnabledEventTypes() is empty — this test would pass vacuously")
	}

	// The default_enabled list and the per-entry flag must agree; they are two
	// views of the same fact and a client may use either.
	gotList := make(map[string]bool, len(resp.DefaultEnabled))
	for _, et := range resp.DefaultEnabled {
		gotList[et] = true
	}
	if len(gotList) != len(resp.DefaultEnabled) {
		t.Errorf("default_enabled contains duplicates: %v", resp.DefaultEnabled)
	}

	for _, et := range resp.EventTypes {
		if et.DefaultEnabled != wantDefaults[et.Type] {
			t.Errorf("event type %q: default_enabled = %v, want %v",
				et.Type, et.DefaultEnabled, wantDefaults[et.Type])
		}
		if et.DefaultEnabled != gotList[et.Type] {
			t.Errorf("event type %q: default_enabled flag = %v but membership of the "+
				"default_enabled list = %v", et.Type, et.DefaultEnabled, gotList[et.Type])
		}
	}

	// sla_breach specifically: the type whose absence meant a missed
	// remediation deadline notified nobody.
	if !gotList[string(integrationdom.EventTypeSLABreach)] {
		t.Errorf("sla_breach is not reported as default-enabled; an SLA breach would "+
			"reach nobody on a channel created with the defaults (got %v)", resp.DefaultEnabled)
	}
}

// TestGetTenantEventTypes_FiltersByTenantModules proves the server is doing the
// module filtering, which is the job a client should not be reimplementing.
func TestGetTenantEventTypes_FiltersByTenantModules(t *testing.T) {
	// A tenant with no optional modules at all: only the module-less system
	// events survive.
	h := newEventTypesHandler(t)

	rec := httptest.NewRecorder()
	h.GetTenantEventTypes(rec, newEventTypesRequest())
	resp := decodeEventTypes(t, rec)

	if len(resp.EventTypes) == 0 {
		t.Fatal("a tenant with no optional modules got zero event types; system events " +
			"require no module and must always be available")
	}
	for _, et := range resp.EventTypes {
		if et.RequiredModule != "" {
			t.Errorf("event type %q requires module %q but the tenant has no modules enabled",
				et.Type, et.RequiredModule)
		}
	}

	// The scans module gates the scan events; without it they must be absent.
	for _, et := range resp.EventTypes {
		if et.Type == string(integrationdom.EventTypeScanCompleted) {
			t.Errorf("scan_completed returned for a tenant without the scans module")
		}
	}

	// ...and present once the module is on, so the filter is a real filter and
	// not an unconditional drop.
	withScans := newEventTypesHandler(t, integrationdom.ModuleScans)
	rec2 := httptest.NewRecorder()
	withScans.GetTenantEventTypes(rec2, newEventTypesRequest())
	resp2 := decodeEventTypes(t, rec2)

	found := false
	for _, et := range resp2.EventTypes {
		if et.Type == string(integrationdom.EventTypeScanCompleted) {
			found = true
		}
	}
	if !found {
		t.Error("scan_completed missing for a tenant WITH the scans module")
	}
}

// TestGetTenantEventTypes_CategoriesCoverEveryReturnedType guards the other
// half of the duplication: a category present on an event type but missing from
// the category list renders as an untitled or "undefined" group. Both the
// approval and workflow categories were in exactly that state client-side.
func TestGetTenantEventTypes_CategoriesCoverEveryReturnedType(t *testing.T) {
	h := newEventTypesHandler(t,
		integrationdom.ModuleAssets,
		integrationdom.ModuleScans,
		integrationdom.ModuleFindings,
	)

	rec := httptest.NewRecorder()
	h.GetTenantEventTypes(rec, newEventTypesRequest())
	resp := decodeEventTypes(t, rec)

	labels := make(map[string]string, len(resp.Categories))
	for _, c := range resp.Categories {
		if c.Label == "" {
			t.Errorf("category %q returned with an empty label", c.Category)
		}
		labels[c.Category] = c.Label
	}
	if len(labels) == 0 {
		t.Fatal("no categories returned — this test would pass vacuously")
	}

	for _, et := range resp.EventTypes {
		if _, ok := labels[et.Category]; !ok {
			t.Errorf("event type %q is in category %q, which has no entry in categories[] — "+
				"a client would render an untitled group", et.Type, et.Category)
		}
	}

	// Approval and workflow specifically, since those are the two categories
	// that were added to the registry without any client learning of them.
	for _, c := range []integrationdom.EventCategory{
		integrationdom.EventCategoryApproval,
		integrationdom.EventCategoryWorkflow,
	} {
		if _, ok := labels[string(c)]; !ok {
			t.Errorf("category %q missing from categories[]", c)
		}
	}
}

// TestGetTenantEventTypes_OmitsEmptyCategories: a tenant without the scans
// module should not be offered an empty "Scan Events" heading.
func TestGetTenantEventTypes_OmitsEmptyCategories(t *testing.T) {
	h := newEventTypesHandler(t)

	rec := httptest.NewRecorder()
	h.GetTenantEventTypes(rec, newEventTypesRequest())
	resp := decodeEventTypes(t, rec)

	for _, c := range resp.Categories {
		if c.Category == string(integrationdom.EventCategoryScan) {
			t.Error("scan category returned for a tenant with no scan event types available")
		}
	}
}
