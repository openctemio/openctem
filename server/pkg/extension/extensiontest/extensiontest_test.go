package extensiontest_test

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/limits"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/extension/example"
	"github.com/openctemio/openctem/server/pkg/extension/extensiontest"
)

func TestDeps(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	d := extensiontest.Deps(nil, example.Extension(), extensiontest.Options{
		Env:    map[string]string{example.ConfigGrantAll: "true", "APP_ENCRYPTION_KEY": "secret"},
		Grants: func(id shared.ID, k limits.GrantKey) bool { return id == a && k == example.Grant },
	})
	if d.Settings.Get(example.ConfigGrantAll) != "true" || d.Settings.Get("APP_ENCRYPTION_KEY") != "" {
		t.Fatal("settings must hand out only the declared keys")
	}
	if d.Entitlements.RequireGrant(context.Background(), a, example.Grant) != nil ||
		d.Entitlements.RequireGrant(context.Background(), b, example.Grant) == nil {
		t.Fatal("entitlements")
	}
	if d.Store != nil {
		t.Fatal("no database, no store")
	}
}
