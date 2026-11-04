package cirun

import (
	"context"
	"strings"
	"testing"

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
	imageID, workload, host, db := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	l := &fakeLinker{assets: []DigestAsset{
		{ID: imageID, Type: "container", SubType: "image"},
		{ID: workload, Type: "kubernetes", SubType: "workload"},
		{ID: host, Type: "host"},
		{ID: db, Type: "database"}, // no relationship from a repository
	}}
	s := &Service{log: logger.NewNop()}
	s.SetImageLinker(l)
	run := &cirun.Run{ID: shared.NewID(), TenantID: shared.NewID(), RepositoryAssetID: shared.NewID(), Repository: "github.com/acme/api"}
	image := "ghcr.io/acme/api\n@" + strings.ToUpper(digest[:7]) + digest[7:]
	if n := s.suggestImageLinks(context.Background(), run, image); n != 3 || l.asked != digest {
		t.Fatalf("suggested %d, asked %q", n, l.asked)
	}
	types := map[shared.ID]string{}
	for _, sg := range l.created {
		types[sg.TargetAssetID()] = sg.RelationshipType()
		if sg.SourceAssetID() != run.RepositoryAssetID || sg.TenantID() != run.TenantID || strings.Contains(sg.Reason(), "\n") {
			t.Fatalf("suggestion = %+v", sg)
		}
	}
	if types[imageID] != "contains" || types[workload] != "deployed_to" || types[host] != "deployed_to" || types[db] != "" {
		t.Fatalf("types = %v", types)
	}
	// No or malformed digest: nothing is looked up.
	l2 := &fakeLinker{}
	s.SetImageLinker(l2)
	for _, d := range []string{"", "ghcr.io/acme/api", "x@sha256:abc", "x@md5:" + strings.Repeat("a", 32)} {
		if n := s.suggestImageLinks(context.Background(), run, d); n != 0 || l2.asked != "" {
			t.Fatalf("image %q: %d %q", d, n, l2.asked)
		}
	}
}
