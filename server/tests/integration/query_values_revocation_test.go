package integration

// Search-box value completion (GET /api/v1/query/values) applies a removed
// data scope on the very next request: no answer computed under the old
// scope is served again.

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/server/internal/app/datascope"
	queryapp "github.com/openctemio/openctem/server/internal/app/query"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func TestQueryValues_ScopeRemovalTakesEffectAtOnce(t *testing.T) {
	r := newRTRig(t)
	_ = r.finding(r.assetA, "new", nil) // severity high, in the member's scope
	_ = r.finding(r.assetB, "new", nil) // outside it
	pdb := &postgres.DB{DB: r.db}
	enf := datascope.New(postgres.NewDataScopeRepository(pdb), func(ctx context.Context) datascope.Caller {
		c, _ := ctx.Value(rtCallerKey{}).(datascope.Caller)
		return c
	}, logger.NewNop())
	svc := queryapp.NewService(postgres.NewQueryExecutor(pdb, 0), enf, logger.NewNop())
	perms := []string{permission.FindingsRead.String()}
	caller := queryapp.Caller{TenantID: r.tenant.String(), UserID: r.member.String(),
		Has: func(p string) bool { return slices.Contains(perms, p) }}
	in := queryapp.ValuesInput{Entity: "findings", Field: "severity"}

	count := func() int64 {
		t.Helper()
		res, err := svc.Values(r.memberCtx(), caller, in)
		require.NoError(t, err)
		require.True(t, res.Counted)
		var n int64
		for _, v := range res.Values {
			n += *v.Count
		}
		return n
	}
	require.Equal(t, int64(1), count(), "the member counts only the finding in their scope")

	// The member loses the asset (a group membership or grant removed).
	r.exec(`DELETE FROM user_accessible_assets WHERE tenant_id = $1 AND user_id = $2`, r.tenant.String(), r.member.String())
	require.Equal(t, int64(0), count(), "the same request right after the removal counts nothing")
}
