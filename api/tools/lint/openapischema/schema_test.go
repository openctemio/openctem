package openapischema

import (
	"testing"
)

const baseSpec = `
definitions:
  handler.Asset:
    type: object
    required: [id]
    properties:
      id: {type: string}
      name: {type: string, description: "old words"}
      tags: {type: array, items: {type: string}}
      status: {type: string, enum: [active, archived]}
  handler.Gone:
    type: object
`

func mustParse(t *testing.T, s string) Definitions {
	t.Helper()
	d, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func kinds(cs []Change) map[string]Change {
	m := map[string]Change{}
	for _, c := range cs {
		m[c.Kind+" "+c.Definition+"."+c.Property] = c
	}
	return m
}

func TestCompareIgnoresCosmetics(t *testing.T) {
	// Property order, descriptions, examples and format do not count.
	head := `
definitions:
  handler.Gone:
    type: object
  handler.Asset:
    type: object
    required: [id]
    properties:
      status: {type: string, enum: [archived, active]}
      tags: {type: array, items: {type: string}}
      name: {type: string, description: "new words", example: x}
      id: {type: string, format: uuid}
`
	if cs := Compare(mustParse(t, baseSpec), mustParse(t, head)); len(cs) != 0 {
		t.Fatalf("cosmetic differences reported: %+v", cs)
	}
}

func TestCompareClassifiesShapeChanges(t *testing.T) {
	head := `
definitions:
  handler.Asset:
    type: object
    required: [id, name]
    properties:
      id: {type: integer}
      name: {type: string}
      status: {type: string, enum: [active]}
      owner: {type: string}
  handler.New:
    type: object
`
	got := kinds(Compare(mustParse(t, baseSpec), mustParse(t, head)))
	for key, breaking := range map[string]bool{
		"definition removed handler.Gone.":            true,
		"definition added handler.New.":               false,
		"property shape changed handler.Asset.id":     true,
		"property shape changed handler.Asset.status": true,
		"property removed handler.Asset.tags":         true,
		"property added handler.Asset.owner":          false,
		"now required handler.Asset.name":             true,
	} {
		c, ok := got[key]
		if !ok {
			t.Errorf("%s: not reported (got %v)", key, got)
			continue
		}
		if c.Breaking() != breaking {
			t.Errorf("%s: Breaking()=%v, want %v", key, c.Breaking(), breaking)
		}
		delete(got, key)
	}
	if len(got) != 0 {
		t.Errorf("unexpected changes: %v", got)
	}
}

func TestCompareRequiredRemovedIsNotBreaking(t *testing.T) {
	head := `
definitions:
  handler.Asset:
    type: object
    properties:
      id: {type: string}
      name: {type: string}
      tags: {type: array, items: {type: string}}
      status: {type: string, enum: [active, archived]}
  handler.Gone:
    type: object
`
	cs := Compare(mustParse(t, baseSpec), mustParse(t, head))
	if len(cs) != 1 || cs[0].Kind != RequiredRemoved || cs[0].Breaking() {
		t.Fatalf("got %+v", cs)
	}
}
