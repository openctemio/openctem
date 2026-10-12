package cirun

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/relationship"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeLinker struct {
	assets  []DigestAsset
	asked   string
	created []*relationship.Suggestion
}

func (f *fakeLinker) AssetsWithImageDigest(_ context.Context, _ shared.ID, digest string, _ shared.ID, _ int) ([]DigestAsset, error) {
	f.asked = digest
	return f.assets, nil
}
func (f *fakeLinker) CreateBatch(_ context.Context, s []*relationship.Suggestion) (int, error) {
	f.created = append(f.created, s...)
	return len(s), nil
}

func TestSuggestImageLinks(t *testing.T) {
	digest := "sha256:" + strings.Repeat("c", 64)
	image, workload, host, db := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	l := &fakeLinker{assets: []DigestAsset{
		{ID: image, Type: "container", SubType: "image"},
		{ID: workload, Type: "kubernetes", SubType: "workload"},
		{ID: host, Type: "host"},
		{ID: db, Type: "database"}, // no relationship from a repository
	}}
	s := &Service{log: logger.NewNop()}
	s.SetImageLinker(l)
	run := &cirun.Run{ID: shared.NewID(), TenantID: shared.NewID(), RepositoryAssetID: shared.NewID(), Repository: "github.com/acme/api"}
	report := &ctis.Report{Metadata: ctis.ReportMetadata{Properties: ctis.Properties{"image_digest": strings.ToUpper(digest[:7]) + digest[7:],
		"container_image": "ghcr.io/acme/api:1\n"}}}
	if n := s.suggestImageLinks(context.Background(), run, report); n != 3 || l.asked != digest {
		t.Fatalf("suggested %d, asked %q", n, l.asked)
	}
	types := map[shared.ID]string{}
	for _, sg := range l.created {
		types[sg.TargetAssetID()] = sg.RelationshipType()
		if sg.SourceAssetID() != run.RepositoryAssetID || sg.TenantID() != run.TenantID || strings.Contains(sg.Reason(), "\n") {
			t.Fatalf("suggestion = %+v", sg)
		}
	}
	if types[image] != "contains" || types[workload] != "deployed_to" || types[host] != "deployed_to" || types[db] != "" {
		t.Fatalf("types = %v", types)
	}
	// No or malformed digest: nothing is looked up.
	l2 := &fakeLinker{}
	s.SetImageLinker(l2)
	for _, d := range []any{nil, "sha256:abc", "md5:" + strings.Repeat("a", 32), 42} {
		props := ctis.Properties{}
		if d != nil {
			props["image_digest"] = d
		}
		if n := s.suggestImageLinks(context.Background(), run, &ctis.Report{Metadata: ctis.ReportMetadata{Properties: props}}); n != 0 || l2.asked != "" {
			t.Fatalf("digest %v: %d %q", d, n, l2.asked)
		}
	}
}
