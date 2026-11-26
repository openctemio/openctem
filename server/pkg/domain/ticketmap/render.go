package ticketmap

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// RenderOptions supplies the platform-owned parts of rendering. They are not
// configurable by a profile.
type RenderOptions struct {
	// Redact removes secret material. It runs on every text value after the
	// template is rendered and before encoding; it cannot be switched off.
	Redact func(string) string
	// EncodeBlock / EncodeInline encode multi-line and one-line text for the
	// tracker's markup (so a value cannot add links, mentions or macros).
	EncodeBlock  func(s string, maxRunes int) string
	EncodeInline func(s string, maxRunes int) string
	// EncodeSummary cleans the one-line plain-text summary (no markup).
	EncodeSummary func(s string, maxRunes int) string
	// Table renders a table block in the tracker's markup.
	Table func(t Table) string
	// Account maps an OpenCTEM user to a tracker account id ("" = unknown).
	Account func(u UserRef) string
	// Creating is true when the issue is being created (create-only rows).
	Creating bool
}

// Rendered is the outbound result for one object.
type Rendered struct {
	// Fields is the tracker field payload: field id → JSON value.
	Fields map[string]any `json:"fields"`
	// Dropped lists rows that were not sent and why.
	Dropped []Issue `json:"dropped,omitempty"`
	// Notes are non-blocking remarks (fallback user used, value redacted).
	Notes []Issue `json:"notes,omitempty"`
}

// note is a non-blocking remark of one rendered row: a stable code, the
// English text and the values the sentence names.
type note struct {
	Code    string
	Message string
	Params  map[string]any
}

var noNote note

func (n note) issue(r Row) Issue {
	return stable([]Issue{{Severity: IssueInfo, Code: n.Code, RowID: r.ID, FieldID: r.Target.FieldID, Message: n.Message, Params: n.Params}})[0]
}

// Text limits of the tracker.
const (
	maxSummaryRunes = 255
	maxTextRunes    = 32000
	maxLabelRunes   = 255
)

// RenderOutbound renders the field payload of one object. meta is used to
// resolve allowed-value ids; it may be nil (names are sent).
//
//nolint:cyclop,gocognit // one switch over field shapes
func RenderOutbound(kind ObjectKind, s Spec, values Values, meta *ProjectMeta, opt RenderOptions) Rendered {
	res := Rendered{Fields: map[string]any{}}
	drop := func(r Row, code, msg string, params map[string]any) {
		res.Dropped = append(res.Dropped, Issue{Severity: IssueWarning, Code: code, RowID: r.ID, FieldID: r.Target.FieldID, Message: msg, Params: params})
	}
	redact := opt.Redact
	if redact == nil {
		redact = func(s string) string { return s }
	}
	// Values above the data level are removed before anything renders, so
	// neither an attribute row nor a template can reach them.
	visible := make(Values, len(values))
	for path, v := range values {
		if a, ok := LookupAttr(kind, path); ok && s.Minimization.Allows(a.Tier) {
			visible[path] = v
		}
	}

	for _, r := range s.Fields {
		if !r.Direction.outbound() {
			continue
		}
		if r.Sync == SyncCreate && !opt.Creating {
			continue
		}
		if r.Direction == DirBoth && r.Winner == WinnerTracker && !opt.Creating {
			continue
		}
		schema := r.Target.Schema
		var fm *FieldMeta
		if meta != nil {
			if f, ok := meta.Field(r.Target.FieldID); ok {
				fm = &f
				schema = f.Schema
			}
		}

		var v Value
		switch r.Source.Kind {
		case SourceConst:
			v = Text(r.Source.Value)
		case SourceTemplate:
			tpl, err := ParseTemplate(kind, r.Source.Template)
			if err != nil {
				drop(r, "template", err.Error(), map[string]any{"detail": err.Error()})
				continue
			}
			withLinks, links := linkSentinels(kind, visible)
			v = Text(tpl.Render(withLinks))
			out, ok, nt := shapeValue(r, v, schema, fm, opt, redact)
			if nt.Code != "" {
				res.Notes = append(res.Notes, nt.issue(r))
			}
			if !ok {
				drop(r, "empty", "no value", nil)
				continue
			}
			if str, isStr := out.(string); isStr {
				for sentinel, url := range links {
					str = strings.ReplaceAll(str, sentinel, url)
				}
				out = str
			}
			res.Fields[r.Target.FieldID] = out
			continue
		case SourceAttr:
			a, ok := LookupAttr(kind, r.Source.Attr)
			if !ok {
				drop(r, "unknown_attr", "unknown attribute", nil)
				continue
			}
			if !s.Minimization.Allows(a.Tier) {
				drop(r, "minimized", "above the data level", nil)
				continue
			}
			v = visible[r.Source.Attr]
			if a.Type == TypeLink && shapeOf(schema) == shapeText && v.Str != nil && *v.Str != "" {
				// A platform-built link (configured base URL + object id):
				// sent as is so the tracker links it.
				res.Fields[r.Target.FieldID] = *v.Str
				continue
			}
		}

		out, ok, nt := shapeValue(r, v, schema, fm, opt, redact)
		if nt.Code != "" {
			res.Notes = append(res.Notes, nt.issue(r))
		}
		if !ok {
			drop(r, "empty", "no value", nil)
			continue
		}
		res.Fields[r.Target.FieldID] = out
	}
	return res
}

// shapeValue converts a value into the JSON the tracker expects for the
// field. ok=false when there is nothing to send.
//
//nolint:cyclop,gocognit // one case per field shape
func shapeValue(r Row, v Value, schema FieldSchema, fm *FieldMeta, opt RenderOptions, redact func(string) string) (any, bool, note) {
	tr := r.Transform
	mapped := func(s string) string {
		if tr.Kind == TransformValueMap {
			if m, ok := tr.Map[s]; ok {
				return m
			}
			return tr.Default
		}
		if s == "" {
			return tr.Default
		}
		return s
	}
	text := func(s string, maxRunes int, block bool) string {
		s = redact(s)
		if block && opt.EncodeBlock != nil {
			return opt.EncodeBlock(s, maxRunes)
		}
		if !block && opt.EncodeInline != nil {
			return opt.EncodeInline(s, maxRunes)
		}
		return truncateRunes(s, maxRunes)
	}
	optionRef := func(name string) map[string]string {
		if fm != nil {
			if id, ok := allowedID(fm.AllowedValues, name); ok {
				return map[string]string{"id": id}
			}
		}
		if schema.Type == fieldTypeOption || schema.Items == fieldTypeOption {
			return map[string]string{"value": name}
		}
		return map[string]string{"name": name}
	}

	switch shapeOf(schema) {
	case shapeText:
		if v.Table != nil {
			if opt.Table != nil {
				return opt.Table(*v.Table), true, noNote
			}
			return text(v.String(), maxTextRunes, true), true, noNote
		}
		var s string
		if tr.Kind == TransformJoin {
			sep := tr.Separator
			if sep == "" {
				sep = ", "
			}
			s = strings.Join(v.Strings(), sep)
		} else {
			s = mapped(v.String())
		}
		if s == "" {
			return nil, false, noNote
		}
		if r.Target.FieldID == "summary" {
			s = redact(strings.Join(strings.Fields(s), " "))
			if opt.EncodeSummary != nil {
				return opt.EncodeSummary(s, maxSummaryRunes), true, noNote
			}
			return truncateRunes(s, maxSummaryRunes), true, noNote
		}
		if r.Source.Kind == SourceTemplate || r.Source.Kind == SourceConst {
			// Admin-written layout: keep the lines, encode each one so no
			// value inside can add markup.
			return truncateRunes(textLines(redact(s), opt), maxTextRunes), true, noNote
		}
		block := r.Target.FieldID == "description" || r.Target.FieldID == "environment" || strings.Contains(s, "\n")
		return text(s, maxTextRunes, block), true, noNote
	case shapeNumber:
		if v.Num == nil {
			return nil, false, noNote
		}
		n := *v.Num
		if tr.Kind == TransformNumber {
			p := math.Pow(10, float64(tr.Round))
			n = math.Round(n*p) / p
		}
		return n, true, noNote
	case shapeDate:
		if v.Time == nil {
			return nil, false, noNote
		}
		if schema.Type == "datetime" {
			return v.Time.UTC().Format("2006-01-02T15:04:05.000-0700"), true, noNote
		}
		return v.Time.UTC().Format(time.DateOnly), true, noNote
	case shapeUser:
		if v.User == nil {
			if tr.FallbackAccount != "" {
				return map[string]string{fieldAccountID: tr.FallbackAccount}, true, note{"note_no_assignee_fallback", "no assignee: the fallback account is used", nil}
			}
			return nil, false, noNote
		}
		acct := ""
		if opt.Account != nil {
			acct = opt.Account(*v.User)
		}
		if acct == "" {
			if tr.FallbackAccount != "" {
				return map[string]string{fieldAccountID: tr.FallbackAccount}, true, note{"note_no_account_fallback", "the user has no tracker account: the fallback account is used", nil}
			}
			return nil, false, note{"note_no_account_unassigned", "the user has no tracker account: left unassigned", nil}
		}
		return map[string]string{fieldAccountID: acct}, true, noNote
	case shapeOption:
		s := redact(mapped(v.String()))
		if s == "" {
			return nil, false, noNote
		}
		if fm != nil && len(fm.AllowedValues) > 0 && !allowedHas(fm.AllowedValues, s) {
			return nil, false, note{"note_value_not_allowed", "value " + s + " is not allowed: field left out", map[string]any{"value": s}}
		}
		return optionRef(s), true, noNote
	case shapeLabels:
		items := v.Strings()
		out := make([]string, 0, len(items))
		seen := map[string]bool{}
		for _, it := range items {
			l := mapped(it)
			if l == "" {
				continue
			}
			l = labelSafe(tr.Prefix + redact(l))
			if l != "" && !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
		if len(out) == 0 {
			return nil, false, noNote
		}
		sort.Strings(out)
		return out, true, noNote
	case shapeOptions:
		items := v.Strings()
		out := make([]map[string]string, 0, len(items))
		for _, it := range items {
			s := redact(mapped(it))
			if s == "" {
				continue
			}
			if fm != nil && len(fm.AllowedValues) > 0 && !allowedHas(fm.AllowedValues, s) {
				continue
			}
			out = append(out, optionRef(s))
		}
		if len(out) == 0 {
			return nil, false, noNote
		}
		return out, true, noNote
	}
	s := mapped(v.String())
	if s == "" {
		return nil, false, noNote
	}
	return text(s, maxTextRunes, false), true, noNote
}

// textLines encodes text line by line (inline encoding keeps no markup).
func textLines(s string, opt RenderOptions) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i, l := range lines {
		if opt.EncodeInline != nil {
			lines[i] = opt.EncodeInline(l, maxTextRunes)
		}
	}
	return strings.Join(lines, "\n")
}

// linkSentinels replaces the platform-built link values with random tokens
// that survive encoding, so the links can be put back as is after the
// template's text is encoded (and its other URLs defanged). The token carries
// a random nonce: text inside a value cannot forge it.
func linkSentinels(kind ObjectKind, values Values) (Values, map[string]string) {
	out := make(Values, len(values))
	links := map[string]string{}
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	n := hex.EncodeToString(nonce[:])
	i := 0
	for path, v := range values {
		a, ok := LookupAttr(kind, path)
		if ok && a.Type == TypeLink && v.Str != nil && *v.Str != "" {
			token := fmt.Sprintf("zzoclink%s%dzz", n, i)
			i++
			links[token] = *v.Str
			out[path] = Text(token)
			continue
		}
		out[path] = v
	}
	return out, links
}

// labelSafe makes a tracker label: no whitespace, bounded.
func labelSafe(s string) string {
	s = strings.Join(strings.Fields(s), "-")
	return truncateRunes(s, maxLabelRunes)
}

// ---------------------------------------------------------------------------
// Inbound field changes.

// FieldChange is one tracker field change (from the changelog).
type FieldChange struct {
	FieldID string
	// To is the new value: a display string, an account id for user fields,
	// a date (YYYY-MM-DD) for date fields.
	To string
}

// Command is one inbound effect for the service layer to apply as the
// integration principal. Capability is the attribute's fixed inbound
// capability; the service checks it again before applying.
type Command struct {
	RowID      string     `json:"row_id"`
	Attr       string     `json:"attr"`
	Capability InboundCap `json:"capability"`
	Value      string     `json:"value"`
	// NeedsApproval: the command opens a request (never a direct change).
	NeedsApproval bool `json:"needs_approval"`
}

// EvaluateInbound turns tracker field changes into commands. Only rows that
// flow in, whose tracker side may win, and whose attribute has an inbound
// capability produce commands; anything else is ignored. The capability comes
// from the catalog, never from the stored spec.
func EvaluateInbound(kind ObjectKind, s Spec, changes []FieldChange) []Command {
	var out []Command
	for _, ch := range changes {
		for _, r := range s.Fields {
			if !r.Direction.inbound() || r.Target.FieldID != ch.FieldID || r.Source.Kind != SourceAttr {
				continue
			}
			if r.Direction == DirBoth && r.Winner == WinnerOpenCTEM {
				continue // OpenCTEM owns it: the next push reverts the edit
			}
			a, ok := LookupAttr(kind, r.Source.Attr)
			if !ok || a.Inbound == InboundNever || a.Inbound == "" {
				continue
			}
			val := ch.To
			if r.Transform.Kind == TransformValueMap {
				val = invert(r.Transform.Map, ch.To)
			}
			out = append(out, Command{
				RowID: r.ID, Attr: a.Path, Capability: a.Inbound, Value: val,
				NeedsApproval: a.Inbound == InboundRequest,
			})
		}
	}
	return out
}

func invert(m map[string]string, v string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(m[k], v) {
			return k
		}
	}
	return v
}

// fieldAccountID is the tracker field that holds an assignee account.
const fieldAccountID = "accountId"
