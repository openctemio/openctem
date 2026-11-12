package integration

import (
	"context"
	"fmt"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// pagedExposures pages like the real repository, including pagination's
// 100-row clamp. Other methods panic through the nil embedded interface.
type pagedExposures struct {
	exposure.Repository
	all []*exposure.ExposureEvent
}

func (p *pagedExposures) List(_ context.Context, _ exposure.Filter, _ exposure.ListOptions, page pagination.Pagination) (pagination.Result[*exposure.ExposureEvent], error) {
	start := min(page.Offset(), len(p.all))
	end := min(start+page.Limit(), len(p.all))
	return pagination.NewResult(p.all[start:end], int64(len(p.all)), page), nil
}

func leakedCredentials(t *testing.T, tenant shared.ID, n int, email func(i int) string) []*exposure.ExposureEvent {
	t.Helper()
	out := make([]*exposure.ExposureEvent, n)
	for i := range out {
		ev, err := exposure.NewExposureEvent(tenant, exposure.EventTypeCredentialLeaked, exposure.SeverityHigh,
			fmt.Sprintf("leak %d", i), "hibp", map[string]any{"email": email(i), "identifier": fmt.Sprintf("id-%d", i)})
		if err != nil {
			t.Fatal(err)
		}
		out[i] = ev
	}
	return out
}

// Both identity views asked for one page of 1000, which pagination clamps to
// 100: leaks past the 100th were invisible.
func TestCredentialIdentityViews_ReadPastFirstPage(t *testing.T) {
	tenant := shared.NewID()
	repo := &pagedExposures{all: leakedCredentials(t, tenant, 250, func(i int) string {
		if i < 100 {
			return "first@example.com"
		}
		return "later@example.com"
	})}
	svc := NewCredentialImportService(repo, nil, logger.NewNop())

	ids, err := svc.ListByIdentity(context.Background(), tenant.String(), CredentialListOptions{}, 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if ids.Total != 2 {
		t.Fatalf("identities = %d, want 2 (the second only appears past the first 100 leaks)", ids.Total)
	}

	got, err := svc.GetExposuresForIdentity(context.Background(), tenant.String(), "later@example.com", 1, 500)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 150 {
		t.Fatalf("later@example.com has %d exposures, want 150", got.Total)
	}
}
