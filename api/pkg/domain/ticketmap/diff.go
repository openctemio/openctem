package ticketmap

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
)

// Change is one difference between two spec versions.
type Change struct {
	Kind string `json:"kind"` // added | removed | changed
	Area string `json:"area"` // field | status_out | status_in | setting
	Key  string `json:"key"`  // row id, state, rule index or setting name
	From any    `json:"from,omitempty"`
	To   any    `json:"to,omitempty"`
}

// DiffSpecs lists what changed from a to b, row by row.
func DiffSpecs(a, b Spec) []Change {
	var out []Change
	ra, rb := map[string]Row{}, map[string]Row{}
	for _, r := range a.Fields {
		ra[r.ID] = r
	}
	for _, r := range b.Fields {
		rb[r.ID] = r
	}
	for _, id := range sortedKeys(ra, rb) {
		x, inA := ra[id]
		y, inB := rb[id]
		switch {
		case !inA:
			out = append(out, Change{Kind: "added", Area: "field", Key: id, To: y})
		case !inB:
			out = append(out, Change{Kind: "removed", Area: "field", Key: id, From: x})
		case !equalJSON(x, y):
			out = append(out, Change{Kind: "changed", Area: "field", Key: id, From: x, To: y})
		}
	}
	sa, sb := a.Status.Outbound, b.Status.Outbound
	for _, k := range sortedKeys(sa, sb) {
		x, inA := sa[k]
		y, inB := sb[k]
		switch {
		case !inA:
			out = append(out, Change{Kind: "added", Area: "status_out", Key: k, To: y})
		case !inB:
			out = append(out, Change{Kind: "removed", Area: "status_out", Key: k, From: x})
		case !equalJSON(x, y):
			out = append(out, Change{Kind: "changed", Area: "status_out", Key: k, From: x, To: y})
		}
	}
	if !equalJSON(a.Status.Inbound, b.Status.Inbound) {
		out = append(out, Change{Kind: "changed", Area: "status_in", Key: "rules", From: a.Status.Inbound, To: b.Status.Inbound})
	}
	settings := []struct {
		name string
		x, y any
	}{
		{"minimization", a.Minimization, b.Minimization},
		{"comments_out", a.CommentsOut, b.CommentsOut},
		{"comments_in", a.CommentsIn, b.CommentsIn},
		{"verifying_label", a.Status.VerifyingLabel, b.Status.VerifyingLabel},
		{"sla_breach_label", a.Status.SLABreachLabel, b.Status.SLABreachLabel},
		{"regression", a.Status.Regression, b.Status.Regression},
	}
	for _, s := range settings {
		if !reflect.DeepEqual(s.x, s.y) {
			out = append(out, Change{Kind: "changed", Area: "setting", Key: s.name, From: s.x, To: s.y})
		}
	}
	return out
}

func sortedKeys[V any](a, b map[string]V) []string {
	seen := map[string]bool{}
	var keys []string
	for k := range a {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range b {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func equalJSON(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}
