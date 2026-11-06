package unit

// GET /integrations/{id}/notification-events (RFC-065 §15.4): the same rule as
// the outbox list. An integration admin who is neither an owner nor a member
// of a private program reads that program's events with its name, handle and
// tag scrubbed from the title, body and errors; an unknown decision answers
// 500 instead of showing the event.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	integrationapp "github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type scrubIntegrationRepo struct {
	integration.Repository
	intg *integration.Integration
}

func (r *scrubIntegrationRepo) GetByID(_ context.Context, id integration.ID) (*integration.Integration, error) {
	if id == r.intg.ID() {
		return r.intg, nil
	}
	return nil, integration.ErrIntegrationNotFound
}

type scrubEventRepo struct {
	outbox.EventRepository
	events []*outbox.Event
}

func (r *scrubEventRepo) ListByIntegration(context.Context, string, int, int) ([]*outbox.Event, int64, error) {
	return r.events, int64(len(r.events)), nil
}

func TestNotificationEventsScrubPrivatePrograms(t *testing.T) {
	tenantID := shared.NewID()
	actor, program := shared.NewID(), shared.NewID()
	findingID := uuid.New()
	now := time.Now()
	intg := integration.NewIntegration(shared.NewID(), tenantID, "slack", integration.CategoryNotification,
		integration.ProviderSlack, integration.AuthTypeAPIKey)
	event := outbox.ReconstituteEvent(outbox.NewID(), tenantID, "new_finding", "finding", &findingID,
		"New high finding in Acme Corp VDP", "Asset tagged program:hackerone:acme-corp", outbox.Severity("high"),
		"/findings/x", nil, outbox.EventStatus("failed"), 1, 1, 0, 1,
		[]outbox.SendResult{{IntegrationID: intg.ID().String(), IntegrationName: "slack", Provider: "slack", Status: "failed",
			Error: "post to Acme Corp VDP channel failed", SentAt: now}},
		"send to Acme Corp VDP failed", 1, now, now)
	delivery := bountyprogram.Delivery{
		Restricted: [][]shared.ID{{program}},
		Programs:   []bountyprogram.DeliveryProgram{{ID: program, Name: "Acme Corp VDP", Handle: "acme-corp", Tag: "program:hackerone:acme-corp"}},
	}

	serve := func(resolver *fakeDeliveryResolver, reader *fakeProgramReader) *httptest.ResponseRecorder {
		svc := integrationapp.NewIntegrationService(&scrubIntegrationRepo{intg: intg}, nil, nil, logger.NewNop())
		svc.SetOutboxEventRepository(&scrubEventRepo{events: []*outbox.Event{event}})
		h := handler.NewIntegrationHandler(svc, validator.New(), logger.NewNop())
		if resolver != nil {
			h.SetProgramScrub(resolver, reader)
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID.String())
		ctx = context.WithValue(ctx, middleware.UserIDKey, actor.String())
		req = req.WithContext(ctx)
		req.SetPathValue("id", intg.ID().String())
		rec := httptest.NewRecorder()
		h.GetNotificationEvents(rec, req)
		return rec
	}
	leaks := func(raw string) []string {
		var out []string
		for _, l := range []string{"Acme Corp VDP", "acme-corp", "program:hackerone"} {
			if strings.Contains(strings.ToLower(raw), strings.ToLower(l)) {
				out = append(out, l)
			}
		}
		return out
	}

	t.Run("non-member admin reads the program scrubbed everywhere", func(t *testing.T) {
		reader := &fakeProgramReader{allowed: map[shared.ID]bool{}}
		rec := serve(&fakeDeliveryResolver{delivery: delivery}, reader)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		if l := leaks(rec.Body.String()); len(l) > 0 {
			t.Errorf("response leaks %v: %s", l, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), bountyprogram.ScrubbedProgram) {
			t.Errorf("no scrub marker: %s", rec.Body.String())
		}
		if len(reader.actors) != 1 || reader.actors[0] != actor {
			t.Errorf("reader asked for %v, want the caller", reader.actors)
		}
		if event.Title() != "New high finding in Acme Corp VDP" {
			t.Errorf("stored event was modified: %q", event.Title())
		}
	})

	t.Run("member or owner reads the event unchanged", func(t *testing.T) {
		rec := serve(&fakeDeliveryResolver{delivery: delivery}, &fakeProgramReader{allowed: map[shared.ID]bool{program: true}})
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Acme Corp VDP") {
			t.Errorf("status %d body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unknown decision answers 500, never the event", func(t *testing.T) {
		for name, tc := range map[string]struct {
			resolver *fakeDeliveryResolver
			reader   *fakeProgramReader
		}{
			"resolver": {&fakeDeliveryResolver{err: errors.New("db down")}, &fakeProgramReader{}},
			"reader":   {&fakeDeliveryResolver{delivery: delivery}, &fakeProgramReader{err: errors.New("db down")}},
		} {
			rec := serve(tc.resolver, tc.reader)
			if rec.Code != http.StatusInternalServerError || len(leaks(rec.Body.String())) > 0 {
				t.Errorf("%s: status %d body %s", name, rec.Code, rec.Body.String())
			}
		}
	})
}
