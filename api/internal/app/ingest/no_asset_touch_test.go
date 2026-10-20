package ingest

import (
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// A report commit used to run "UPDATE assets SET updated_at = NOW()" over every
// touched asset to "refresh finding counts". The asset counts are computed at
// read time, so that write only added a non-HOT row version (55 indexes) per
// touched asset per report; the asset upsert already stamps updated_at when it
// sees the asset. The asset repository and processor must not offer it again.
func TestAssetRepositoryHasNoFindingCountTouch(t *testing.T) {
	if _, ok := reflect.TypeOf((*asset.Repository)(nil)).Elem().MethodByName("UpdateFindingCounts"); ok {
		t.Fatal("asset.Repository.UpdateFindingCounts is back: it rewrites every touched asset row for no stored count")
	}
	if _, ok := reflect.TypeOf(&AssetProcessor{}).MethodByName("UpdateFindingCounts"); ok {
		t.Fatal("AssetProcessor.UpdateFindingCounts is back")
	}
}
