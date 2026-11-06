package unit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// user_ids must narrow the members list with or without include=user: the
// plain path used to ignore it and return the whole page.
func TestListMembers_UserIDsFilterAppliesOnBothPaths(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	for _, query := range []string{"", "&include=user"} {
		repo := newMockTenantRepo()
		_, tid := createTenantWithSettings(repo)
		repo.memberSearchResult = &tenant.MemberSearchResult{}
		h := newTenantHandlerForScoring(repo)

		req := withTeamContext(httptest.NewRequest(http.MethodGet,
			"/api/v1/tenants/current/members?user_ids="+a.String()+","+b.String()+query, nil), tid)
		w := httptest.NewRecorder()
		h.ListMembers(w, req)

		assert.Equal(t, http.StatusOK, w.Code, query)
		got := repo.lastMemberFilters.UserIDs
		assert.Len(t, got, 2, "user_ids ignored for query %q", query)
	}
}
