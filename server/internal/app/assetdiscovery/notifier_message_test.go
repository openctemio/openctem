package assetdiscovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func nestedCode(t *testing.T, m *notification.Message, key string) string {
	t.Helper()
	n, ok := m.Params[key].(*notification.Message)
	require.True(t, ok, key)
	return n.Code
}

func TestDescribeMessage_Codes(t *testing.T) {
	a := assetRef{id: shared.NewID(), name: "b.example.com", typ: "domain", exposure: "public"}
	c := assetRef{id: shared.NewID(), name: "a.example.com", typ: "", exposure: "Odd Value", becameExposed: true}

	m := describeMessage([]assetRef{a}, 1, 0, 0, "")
	assert.Equal(t, "asset.discovered_one", m.Code)
	assert.Equal(t, "b.example.com", m.Params["asset"])
	assert.Equal(t, "asset.type.domain", nestedCode(t, m, "asset_type"))
	assert.Equal(t, "asset.exposure.public", nestedCode(t, m, "exposure"))

	m = describeMessage([]assetRef{c}, 1, 1, 0, "")
	assert.Equal(t, "asset.exposed_one", m.Code)
	assert.Equal(t, "asset.type.other", nestedCode(t, m, "asset_type"))
	assert.Equal(t, "asset.exposure.other", nestedCode(t, m, "exposure"))

	m = describeMessage([]assetRef{a, c}, 5, 0, 0, "")
	assert.Equal(t, "asset.discovered_many", m.Code)
	assert.Equal(t, 5, m.Params["count"])
	assert.Equal(t, "a.example.com, b.example.com", m.Params["names"])
	assert.Equal(t, 3, m.Params["more"])
	assert.Equal(t, 0, m.Params["shared_count"])

	m = describeMessage([]assetRef{a, c}, 5, 5, 2, "Acme CDN")
	assert.Equal(t, "asset.exposed_many", m.Code)
	assert.Equal(t, 2, m.Params["shared_count"])
	assert.Equal(t, "Acme CDN", m.Params["edge"])

	m = describeMessage([]assetRef{a, c}, 5, 2, 0, "")
	assert.Equal(t, "asset.exposed_mixed", m.Code)
	assert.Equal(t, 3, m.Params["new_count"])
	assert.Equal(t, 2, m.Params["existing_count"])

	m = describeMessage([]assetRef{a, c}, 2, 0, 2, "Acme CDN")
	assert.Equal(t, "asset.discovered_shared_edge", m.Code)
	assert.Equal(t, 2, m.Params["count"])
	assert.Equal(t, "Acme CDN", m.Params["edge"])
}
