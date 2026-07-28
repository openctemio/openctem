package postgres

import (
	"context"
	"database/sql"
	"os"
	"regexp"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// ingest_channel records who reported a finding — a scanner we ran, an
// integration, a collector, or a person — as distinct from `source`, which
// records the technique. See docs/architecture/decisions/004-finding-provenance.md.
//
// These tests exist because the write path is three duplicated INSERT column
// lists, their argument blocks, an ON CONFLICT set, and the scan/reconstruct
// pair. A column added to the list but not the arguments shifts every parameter
// after it, and Postgres will happily accept the result as long as the types
// line up — the finding is stored with someone else's data in it. Only a
// round-trip catches that: write through the repository, read back through the
// repository, compare.
//
// An earlier attempt at exactly this change patched the column lists with a
// script, and the third edit landed inside ListActiveCVEsByTenant. That is what
// these tests are for.

func openIngestChannelDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping ingest_channel round-trip")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

// A finding written with a channel must come back with the same channel, and
// with every neighboring field intact — the whole point is to detect an
// argument shift, so the assertions deliberately cover fields either side of
// the new column.
func TestCreate_PersistsIngestChannel(t *testing.T) {
	db := openIngestChannelDB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)

	for _, channel := range vulnerability.AllIngestChannels() {
		t.Run(string(channel), func(t *testing.T) {
			// A distinct asset per case: the fingerprint is derived from the
			// asset, so sharing one makes the second insert a duplicate.
			assetID := seedTestAsset(ctx, t, db, tenantID)
			f, err := vulnerability.NewFinding(
				tenantID, assetID,
				vulnerability.FindingSourceVA,
				"probe-tool",
				vulnerability.SeverityHigh,
				"probe message",
			)
			if err != nil {
				t.Fatalf("new finding: %v", err)
			}
			// A distinct fingerprint per case: Create rejects a duplicate, and
			// NewFinding leaves it empty, so all four would collide.
			f.SetFingerprint("probe-" + string(channel) + "-" + f.ID().String())
			f.SetIngestChannel(channel)

			if err := repo.Create(ctx, f); err != nil {
				t.Fatalf("create: %v", err)
			}

			got, err := repo.GetByID(ctx, tenantID, f.ID())
			if err != nil {
				t.Fatalf("read back: %v", err)
			}

			if got.IngestChannel() != channel {
				t.Errorf("ingest_channel round-trip: got %q, want %q", got.IngestChannel(), channel)
			}
			// Neighbors. If a placeholder shifted, these land in the wrong
			// columns and this is where it shows.
			if got.Source() != vulnerability.FindingSourceVA {
				t.Errorf("source: got %q, want va — a shifted argument would land here", got.Source())
			}
			if got.ToolName() != "probe-tool" {
				t.Errorf("tool_name: got %q, want probe-tool", got.ToolName())
			}
			if got.Severity() != vulnerability.SeverityHigh {
				t.Errorf("severity: got %q, want high", got.Severity())
			}
		})
	}
}

// Not setting a channel must store NULL, not an empty string. The column is a
// Postgres enum and ” is not a member, so an empty write fails the insert and
// takes the whole finding with it.
func TestCreate_UnsetIngestChannelIsNull(t *testing.T) {
	db := openIngestChannelDB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	f, err := vulnerability.NewFinding(
		tenantID, assetID,
		vulnerability.FindingSourceSAST,
		"probe-tool",
		vulnerability.SeverityLow,
		"probe message",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}

	f.SetFingerprint("probe-nochannel-" + f.ID().String())

	if err := repo.Create(ctx, f); err != nil {
		t.Fatalf("create with no channel must not fail: %v", err)
	}

	var isNull bool
	if err := db.QueryRowContext(ctx,
		`SELECT ingest_channel IS NULL FROM findings WHERE id = $1`, f.ID().String()).Scan(&isNull); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !isNull {
		t.Error("an unset channel must store NULL, so 'unrecorded' stays distinguishable from a real value")
	}

	got, err := repo.GetByID(ctx, tenantID, f.ID())
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.IngestChannel() != "" {
		t.Errorf("NULL must read back as empty, got %q", got.IngestChannel())
	}
}

// An invalid value must never reach the database. The column is an enum, so a
// bad value fails the insert — losing the finding entirely over a provenance
// label nobody asked for.
func TestSetIngestChannel_RejectsInvalid(t *testing.T) {
	f, err := vulnerability.NewFinding(
		shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceSAST, "t", vulnerability.SeverityLow, "m",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}

	for _, bad := range []vulnerability.IngestChannel{"", "SCANNER", "agent", "integration "} {
		f.SetIngestChannel(bad)
		if f.IngestChannel() != "" {
			t.Errorf("SetIngestChannel(%q) stored %q; invalid values must be ignored", bad, f.IngestChannel())
		}
	}
}

// findingInsertColumnCount carries the comment "It MUST stay in sync with
// findingInsertColumnsSQL and findingInsertArgs" and nothing checked it. A
// column added to the list without a matching argument shifts every parameter
// after it, and Postgres accepts the result whenever the types happen to line
// up — the row is stored with the wrong data in it and nothing errors.
//
// No database required.
func TestFindingInsert_ColumnsPlaceholdersAndArgsAgree(t *testing.T) {
	cols := findingInsertColumnsSQL()
	inner := cols[strings.Index(cols, "(")+1 : strings.LastIndex(cols, ")")]

	columnCount := 0
	for _, c := range strings.Split(strings.ReplaceAll(inner, "\n", ""), ",") {
		if strings.TrimSpace(c) != "" {
			columnCount++
		}
	}
	if columnCount != findingInsertColumnCount {
		t.Errorf("findingInsertColumnsSQL lists %d columns, findingInsertColumnCount says %d",
			columnCount, findingInsertColumnCount)
	}

	placeholders := len(regexp.MustCompile(`\$\d+`).FindAllString(findingValuesPlaceholders(1), -1))
	if placeholders != columnCount {
		t.Errorf("findingValuesPlaceholders emits %d placeholders for %d columns",
			placeholders, columnCount)
	}

	f, err := vulnerability.NewFinding(
		shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceSAST, "t", vulnerability.SeverityLow, "m",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	args, err := findingInsertArgs(f)
	if err != nil {
		t.Fatalf("findingInsertArgs: %v", err)
	}
	if len(args) != columnCount {
		t.Errorf("findingInsertArgs returns %d values for %d columns — every parameter after "+
			"the mismatch is written into the wrong column", len(args), columnCount)
	}
}
