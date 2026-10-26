package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/operation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The SQL stale interval and the domain constant describe the same rule.
func TestOperationStaleSQLMatches(t *testing.T) {
	if operation.StaleAfter.Minutes() != 5 || operationStaleSQL != "interval '5 minutes'" {
		t.Fatalf("operation.StaleAfter = %v, SQL %s: keep them equal", operation.StaleAfter, operationStaleSQL)
	}
}

// The budget is checked by the insert under a per-tenant lock: people who
// create at the same moment cannot overrun it together, and another
// tenant's operations do not count. Requires DATABASE_URL.
func TestOperationCreate_BudgetHoldsUnderConcurrency_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.Ping(); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	ctx := context.Background()
	repo := NewOperationRepository(&DB{DB: raw})

	seedTenant := func() shared.ID {
		id := shared.NewID()
		if _, err := raw.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "op-budget-"+id.String()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = raw.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id.String()) })
		return id
	}
	tenant, other := seedTenant(), seedTenant()
	const people = 8
	users := make([]shared.ID, people)
	for i := range users {
		users[i] = shared.NewID()
		if _, err := raw.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'op budget')`,
			users[i].String(), users[i].String()+"@op.test"); err != nil {
			t.Fatal(err)
		}
		u := users[i]
		t.Cleanup(func() { _, _ = raw.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.String()) })
	}
	budget := operation.Budget{Kinds: []operation.Kind{operation.KindFindingsBulkStatus}, Since: time.Now().Add(-time.Hour), Max: 10}
	// Another tenant's spent budget does not count here.
	if _, _, err := repo.Create(ctx, &operation.Operation{TenantID: other, CreatedBy: users[0], Kind: operation.KindFindingsBulkStatus, Total: 10}, budget); err != nil {
		t.Fatal(err)
	}

	// Eight people each ask for 6 of a budget of 10 at once: exactly one fits.
	var wg sync.WaitGroup
	var mu sync.Mutex
	created, refused := 0, 0
	var winner shared.ID
	for i := range people {
		wg.Add(1)
		go func(u shared.ID) {
			defer wg.Done()
			_, _, err := repo.Create(ctx, &operation.Operation{TenantID: tenant, CreatedBy: u, Kind: operation.KindFindingsBulkStatus, Total: 6}, budget)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				created++
				winner = u
			case errors.Is(err, operation.ErrBudget):
				refused++
			default:
				t.Errorf("create: %v", err)
			}
		}(users[i])
	}
	wg.Wait()
	if created != 1 || refused != people-1 {
		t.Fatalf("created %d, refused %d; want 1 and %d", created, refused, people-1)
	}
	// Which person wins the race is not fixed, and a person with an operation
	// still running is refused for that reason, not for the budget: the later
	// steps use people other than the winner.
	free := make([]shared.ID, 0, people)
	for _, u := range users {
		if u != winner {
			free = append(free, u)
		}
	}
	// A create that is still in flight (its row not committed yet) holds the
	// budget: the next create waits for it and then sees its row.
	inFlight, err := raw.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inFlight.Rollback() }()
	if _, err := inFlight.ExecContext(ctx, operationBudgetLockSQL, tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := inFlight.ExecContext(ctx, `INSERT INTO operations (tenant_id, created_by, kind, status, total)
		VALUES ($1, $2, 'findings_bulk_status', 'succeeded', 3)`, tenant.String(), free[0].String()); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() {
		_, _, err := repo.Create(ctx, &operation.Operation{TenantID: tenant, CreatedBy: free[1], Kind: operation.KindFindingsBulkStatus, Total: 2}, budget)
		waited <- err
	}()
	time.Sleep(300 * time.Millisecond)
	if err := inFlight.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-waited; !errors.Is(err, operation.ErrBudget) {
		t.Fatalf("create next to an in-flight one = %v, want ErrBudget (6 + 3 + 2 > 10)", err)
	}

	// What is left still fits: 1 more.
	if _, _, err := repo.Create(ctx, &operation.Operation{TenantID: tenant, CreatedBy: free[2], Kind: operation.KindFindingsBulkStatus, Total: 1}, budget); err != nil {
		t.Fatalf("the rest of the budget: %v", err)
	}
	if _, _, err := repo.Create(ctx, &operation.Operation{TenantID: tenant, CreatedBy: free[3], Kind: operation.KindFindingsBulkStatus, Total: 1}, budget); !errors.Is(err, operation.ErrBudget) {
		t.Fatalf("over the budget: %v, want ErrBudget", err)
	}
}
