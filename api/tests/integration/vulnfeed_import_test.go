package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/vulnfeed"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

// The collector's golden bundle (real NVD data) imported into the corpus by
// the real importer and repositories.
func TestVulnFeedImport_GoldenBundle(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	pdb := &postgres.DB{DB: db}
	ctx := context.Background()
	dir := "../../pkg/vulnbundle/testdata/golden"
	root, err := os.ReadFile(filepath.Join(dir, "root-keyid.txt"))
	require.NoError(t, err)

	_, err = db.Exec(`UPDATE threat_intel_sync_status SET is_enabled = true, metadata = '{}'::jsonb WHERE source_name = 'vulnfeed'`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.Exec(`UPDATE threat_intel_sync_status SET is_enabled = false, metadata = '{}'::jsonb WHERE source_name = 'vulnfeed'`)
	})

	ti := postgres.NewThreatIntelRepository(pdb)
	im, err := vulnfeed.NewImporter(vulnfeed.Config{RootKeyID: strings.TrimSpace(string(root)), BundleDir: dir},
		postgres.NewCVECorpusRepository(pdb), ti.SyncStatus(), postgres.NewSoftwareRepository(pdb), logger.NewNop())
	require.NoError(t, err)
	// The golden bundle's own clock (it expires a week after it was made).
	raw, _ := os.ReadFile(filepath.Join(dir, vulnbundle.LatestFile))
	var env scannertemplate.Envelope
	require.NoError(t, json.Unmarshal(raw, &env))
	var l vulnbundle.Latest
	require.NoError(t, json.Unmarshal(env.Payload, &l))
	vulnfeed.SetClockForTest(im, func() time.Time { return l.CreatedAt.Add(time.Hour) })

	res, err := im.Run(ctx)
	require.NoError(t, err)
	assert.True(t, res.Ran)
	assert.Equal(t, uint64(2), res.Sequence)

	v, err := vulnbundle.VerifyDir(dir, vulnbundle.Options{PinnedRoot: strings.TrimSpace(string(root)), Now: l.CreatedAt.Add(time.Hour)})
	require.NoError(t, err)
	recs, err := v.Read(v.Snapshot)
	require.NoError(t, err)
	ids := make([]string, 0, len(recs.CVEs))
	want := 0
	for _, c := range recs.CVEs {
		ids = append(ids, c.ID)
		want += len(c.Ranges)
	}
	var stored, ranges int
	require.NoError(t, db.QueryRow(`SELECT (SELECT count(*) FROM cve_records WHERE cve_id = ANY($1)),
		(SELECT count(*) FROM vulnerability_affected WHERE cve_id = ANY($1))`, pq.Array(ids)).Scan(&stored, &ranges))
	assert.Equal(t, len(ids), stored)
	assert.Equal(t, want, ranges)

	var status string
	var meta []byte
	require.NoError(t, db.QueryRow(`SELECT last_sync_status, metadata FROM threat_intel_sync_status WHERE source_name = 'vulnfeed'`).Scan(&status, &meta))
	assert.Equal(t, "success", status)
	assert.Contains(t, string(meta), `"applied_sequence": 2`)

	// Re-running finds nothing newer.
	res, err = im.Run(ctx)
	require.NoError(t, err)
	assert.False(t, res.Ran)
}
