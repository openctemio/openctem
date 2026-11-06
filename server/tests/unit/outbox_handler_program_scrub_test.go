package unit

// The notification outbox list and detail (RFC-065 §15.4): an integration
// admin who is neither an owner nor a member of a private program reads
// that program's events with its name, handle and tag scrubbed; an unknown
// decision answers 500 instead of showing the entry.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

type scrubOutboxRepo struct {
	outbox.OutboxRepository
	entries []*outbox.Outbox
}

func (r *scrubOutboxRepo) List(_ context.Context, f outbox.OutboxFilter, p pagination.Pagination) (pagination.Result[*outbox.Outbox], error) {
	var out []*outbox.Outbox
	for _, e := range r.entries {
		if f.TenantID != nil && e.TenantID() == *f.TenantID {
			out = append(out, e)
		}
	}
	return pagination.Result[*outbox.Outbox]{Data: out, Total: int64(len(out)), Page: 1, PerPage: 20, TotalPages: 1}, nil
}

func (r *scrubOutboxRepo) GetByID(_ context.Context, id outbox.ID) (*outbox.Outbox, error) {
	for _, e := range r.entries {
		if e.ID() == id {
			return e, nil
		}
	}
	return nil, outbox.ErrOutboxNotFound
}

type fakeProgramReader struct {
	allowed map[shared.ID]bool
	err     error
	actors  []shared.ID
}

func (f *fakeProgramReader) ReadablePrograms(_ context.Context, _, actor shared.ID, _ []shared.ID) (map[shared.ID]bool, error) {
	f.actors = append(f.actors, actor)
	return f.allowed, f.err
}

func TestOutboxHandlerScrubsPrivatePrograms(t *testing.T) {
	tenantID, otherTenant := shared.NewID(), shared.NewID()
	actor := shared.NewID()
	program := shared.NewID()
	findingID := uuid.New()
	now := time.Now()
	meta := map[string]any{
		"asset_name": "api.acme-corp.example",
		"tags":       []any{"program:hackerone:acme-corp", "prod"},
		"assets":     []any{map[string]any{"id": uuid.NewString(), "name": "Acme Corp VDP portal"}},
	}
	entry := outbox.Reconstitute(outbox.NewID(), tenantID, "new_finding", "finding", &findingID,
		"New high finding in Acme Corp VDP", "Asset tagged program:hackerone:acme-corp", outbox.Severity("high"),
		"/findings/x", meta, outbox.OutboxStatusFailed, 1, 3, "send to Acme Corp VDP failed", now, nil, "", now, now, nil)
	foreign := outbox.Reconstitute(outbox.NewID(), otherTenant, "new_finding", "finding", &findingID,
		"Acme Corp VDP", "", outbox.Severity("high"), "", nil, outbox.OutboxStatusPending, 0, 3, "", now, nil, "", now, now, nil)
	delivery := bountyprogram.Delivery{
		Restricted: [][]shared.ID{{program}},
		Programs:   []bountyprogram.DeliveryProgram{{ID: program, Name: "Acme Corp VDP", Handle: "acme-corp", Tag: "program:hackerone:acme-corp"}},
	}

	serve := func(t *testing.T, resolver *fakeDeliveryResolver, reader *fakeProgramReader, path string, get bool) *httptest.ResponseRecorder {
		t.Helper()
		h := handler.NewOutboxHandler(&scrubOutboxRepo{entries: []*outbox.Outbox{entry, foreign}}, logger.NewNop())
		if resolver != nil {
			h.SetProgramScrub(resolver, reader)
		}
		req := httptest.NewRequest(http.MethodGet, path, nil)
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID.String())
		ctx = context.WithValue(ctx, middleware.UserIDKey, actor.String())
		rctx := chi.NewRouteContext()
		if get {
			rctx.URLParams.Add("id", strings.TrimPrefix(path, "/"))
		}
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
		rec := httptest.NewRecorder()
		if get {
			h.Get(rec, req.WithContext(ctx))
		} else {
			h.List(rec, req.WithContext(ctx))
		}
		return rec
	}
	list := func(t *testing.T, rec *httptest.ResponseRecorder) []handler.OutboxEntryResponse {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var res pagination.Result[handler.OutboxEntryResponse]
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		return res.Data
	}

	t.Run("non-member admin reads the program scrubbed everywhere", func(t *testing.T) {
		reader := &fakeProgramReader{allowed: map[shared.ID]bool{}}
		rec := serve(t, &fakeDeliveryResolver{delivery: delivery}, reader, "/", false)
		items := list(t, rec)
		if len(items) != 1 {
			t.Fatalf("want only the tenant entry, got %d", len(items))
		}
		raw := rec.Body.String()
		for _, leak := range []string{"Acme Corp VDP", "acme-corp", "program:hackerone"} {
			if strings.Contains(strings.ToLower(raw), strings.ToLower(leak)) {
				t.Errorf("response leaks %q: %s", leak, raw)
			}
		}
		if items[0].Title != "New high finding in "+bountyprogram.ScrubbedProgram {
			t.Errorf("title = %q", items[0].Title)
		}
		if len(reader.actors) != 1 || reader.actors[0] != actor {
			t.Errorf("reader asked for %v, want the caller", reader.actors)
		}
		// The stored entry is untouched.
		if entry.Title() != "New high finding in Acme Corp VDP" || entry.Metadata()["asset_name"] != "api.acme-corp.example" {
			t.Errorf("stored entry was modified: %q %v", entry.Title(), entry.Metadata())
		}
	})

	t.Run("member or owner reads the entry unchanged", func(t *testing.T) {
		reader := &fakeProgramReader{allowed: map[shared.ID]bool{program: true}}
		items := list(t, serve(t, &fakeDeliveryResolver{delivery: delivery}, reader, "/", false))
		if items[0].Title != "New high finding in Acme Corp VDP" || items[0].Metadata["asset_name"] != "api.acme-corp.example" {
			t.Errorf("member got scrubbed entry: %+v", items[0])
		}
	})

	t.Run("event about no private program is not checked", func(t *testing.T) {
		reader := &fakeProgramReader{}
		items := list(t, serve(t, &fakeDeliveryResolver{}, reader, "/", false))
		if items[0].Title != "New high finding in Acme Corp VDP" || len(reader.actors) != 0 {
			t.Errorf("title %q, reader calls %d", items[0].Title, len(reader.actors))
		}
	})

	t.Run("unknown decision answers 500, never the entry", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			resolver *fakeDeliveryResolver
			reader   *fakeProgramReader
		}{
			{"resolver", &fakeDeliveryResolver{err: errors.New("db down")}, &fakeProgramReader{}},
			{"reader", &fakeDeliveryResolver{delivery: delivery}, &fakeProgramReader{err: errors.New("db down")}},
		} {
			rec := serve(t, tc.resolver, tc.reader, "/", false)
			if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "Acme") {
				t.Errorf("%s: status %d body %s", tc.name, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("detail view is scrubbed too", func(t *testing.T) {
		rec := serve(t, &fakeDeliveryResolver{delivery: delivery}, &fakeProgramReader{allowed: map[shared.ID]bool{}}, "/"+entry.ID().String(), true)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "Acme") {
			t.Errorf("status %d body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("another tenant entry stays not found", func(t *testing.T) {
		rec := serve(t, &fakeDeliveryResolver{delivery: delivery}, &fakeProgramReader{allowed: map[shared.ID]bool{program: true}}, "/"+foreign.ID().String(), true)
		if rec.Code != http.StatusNotFound {
			t.Errorf("status %d", rec.Code)
		}
	})
}
