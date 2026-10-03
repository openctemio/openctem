package handler

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// The update API allowed 20 tags while ingest kept 50, so an asset a scanner
// had tagged 21 times could not be saved from the UI. Every asset request
// now validates the same cap as the domain and ingest (owner decision D5).
func TestAssetRequestTagCapMatchesTheDomain(t *testing.T) {
	if ingest.MaxTagsPerAsset != asset.MaxTagsPerAsset {
		t.Fatalf("ingest cap %d != domain cap %d", ingest.MaxTagsPerAsset, asset.MaxTagsPerAsset)
	}

	want := fmt.Sprintf("max=%d,dive,max=%d", asset.MaxTagsPerAsset, asset.MaxTagLength)
	for _, req := range []any{CreateAssetRequest{}, UpdateAssetRequest{}, CreateRepositoryAssetRequest{}} {
		typ := reflect.TypeOf(req)
		f, ok := typ.FieldByName("Tags")
		if !ok {
			t.Fatalf("%s has no Tags field", typ.Name())
		}
		if tag := f.Tag.Get("validate"); !strings.Contains(tag, want) {
			t.Errorf("%s.Tags validate=%q, want it to contain %q", typ.Name(), tag, want)
		}
	}
}

func TestUpdateAssetRequestAcceptsFiftyTagsAndRefusesMore(t *testing.T) {
	v := validator.New()
	tags := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("tag-%d", i)
		}
		return out
	}

	if err := v.Validate(UpdateAssetRequest{Tags: tags(21)}); err != nil {
		t.Fatalf("21 tags refused (the old cap of 20): %v", err)
	}
	if err := v.Validate(UpdateAssetRequest{Tags: tags(asset.MaxTagsPerAsset)}); err != nil {
		t.Fatalf("%d tags refused: %v", asset.MaxTagsPerAsset, err)
	}
	if err := v.Validate(UpdateAssetRequest{Tags: tags(asset.MaxTagsPerAsset + 1)}); err == nil {
		t.Fatalf("%d tags accepted, want a validation error", asset.MaxTagsPerAsset+1)
	}
}
