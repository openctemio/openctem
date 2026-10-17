package integration

// A CI SCA upload carries a dependency list trimmed to the vulnerable
// packages and the packages on their paths (testdata/ci_sca). Through the
// real upload path it must not delete the rest of a lockfile another
// producer stored for the same file on the same repository.

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
)

// ciSCAReport is the trimmed trivy npm fixture as a CI upload body for repo.
func ciSCAReport(t *testing.T, repo string) map[string]any {
	t.Helper()
	b, err := os.ReadFile("testdata/ci_sca/trivy-npm-trimmed.json")
	if err != nil {
		t.Fatal(err)
	}
	var rep ctis.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	rep.Metadata.ID = shared.NewID().String()
	rep.Assets[0].Value = repo
	return map[string]any{"report": rep}
}

// ciSCAUpload exchanges a token for a run on acme/api and uploads the
// fixture; it returns the repository asset.
func ciSCAUpload(t *testing.T, r *ciRig, tenant shared.ID, cfg *cirun.TrustConfig, repoName string) shared.ID {
	t.Helper()
	code, ex := r.exchange(tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", "5555555555555555555555555555555555555555", nil))
	if code != http.StatusCreated {
		t.Fatalf("exchange: %d %v", code, ex)
	}
	if resp, out := r.post("/api/v1/ci/runs/"+ex["run_id"].(string)+"/results", ex["token"].(string), ciSCAReport(t, repoName)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d %v", resp.StatusCode, out)
	}
	return shared.MustIDFromString(ex["repository_asset_id"].(string))
}

func assetPackageChannels(t *testing.T, r *ciRig, tenant, asset shared.ID) map[string]string {
	t.Helper()
	rows, err := r.db.QueryContext(context.Background(), `SELECT v.purl, COALESCE(s.channel, '') FROM asset_software s
		JOIN software_versions v ON v.id = s.software_version_id
		WHERE s.tenant_id = $1 AND s.asset_id = $2 AND s.source = 'package' AND s.location = 'package-lock.json'`,
		tenant.String(), asset.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var p, c string
		if err := rows.Scan(&p, &c); err != nil {
			t.Fatal(err)
		}
		out[p] = c
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCISCAUpload_KeepsAnotherProducersPackageList(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	repoName := strings.ToLower(strings.TrimPrefix(r.idp.srv.URL, "https://")) + "/acme/api"

	asset := ciSCAUpload(t, r, r.tenant, cfg, repoName)
	if got := assetPackageChannels(t, r, r.tenant, asset); len(got) != 4 || got["pkg:npm/express@4.17.1"] != software.ChannelCI {
		t.Fatalf("after the first CI upload: %v, want the 4 packages of the trimmed list", got)
	}

	// An SBOM upload stores the whole lockfile of the same repository.
	full := []string{"pkg:npm/express@4.17.1", "pkg:npm/body-parser@1.19.0", "pkg:npm/qs@6.7.0", "pkg:npm/lodash@4.17.20",
		"pkg:npm/accepts@1.3.8", "pkg:npm/cookie@0.4.0", "pkg:npm/vary@1.1.2"}
	nodes := make([]software.PackageNode, 0, len(full))
	for _, s := range full {
		p, err := software.ParsePURL(s)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, software.PackageNode{Ref: s, PURL: p, DisplayName: p.Name, Location: "package-lock.json"})
	}
	if _, err := postgres.NewComponentRepository(r.db).WritePackages(ctx, r.tenant, software.PackageSnapshot{
		AssetID: asset, Channel: software.ChannelSBOMUpload, Replace: true, Packages: nodes}); err != nil {
		t.Fatal(err)
	}

	// The next CI run uploads its trimmed list again: nothing the SBOM
	// listed is removed, and the links stay with the SBOM.
	if again := ciSCAUpload(t, r, r.tenant, cfg, repoName); again != asset {
		t.Fatalf("second run bound to %s, want %s", again, asset)
	}
	got := assetPackageChannels(t, r, r.tenant, asset)
	if len(got) != len(full) {
		t.Fatalf("after the second CI upload: %v, want the SBOM's %d packages", got, len(full))
	}
	for _, s := range full {
		if got[s] != software.ChannelSBOMUpload {
			t.Errorf("%s channel %q, want the SBOM's", s, got[s])
		}
	}
}
