package ingest

import (
	"reflect"
	"slices"
	"strconv"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/safetext"
)

// E-mail addresses are personal data the platform never stores
// (research/292). A scanner reports them as a finding's text (an extractor
// template's results, a page that lists its staff, a response body kept as
// evidence), whatever tool sent the report. maskReportEmails is the
// receiver's rule, for every tool: before anything is stored, fingerprinted,
// quarantined or logged, the local part of every address in a finding's
// text and evidence becomes "***" and the domain is kept
// (safetext.MaskEmails). The sensor also never runs the templates that only
// harvest personal data; this is the defense in depth behind it.
//
// The identifiers a report uses to bind a finding (its id, asset ref,
// fingerprints, correlation id, dependency ref, source refs, native identity,
// the tool) are not text and are left alone. Evidence offsets (marked
// sensitive spans, body match ranges) move with the masked text, so a span
// still marks its secret. Idempotent: a masked address is not an address.

// emailMaskSkipped are the finding members that identify rather than
// describe.
var emailMaskSkipped = map[string]bool{ //nolint:gochecknoglobals // static table
	"ID": true, "AssetRef": true, "Fingerprint": true, "PartialFingerprints": true, "CorrelationID": true,
	"DependencyRef": true, "SourceRefs": true, "Native": true, "Tool": true, "EvidenceItems": true,
}

// maxEmailMaskDepth bounds the walk of nested properties.
const maxEmailMaskDepth = 32

// maskReportEmails masks the e-mail addresses in every finding of report
// (see the file comment). It returns how many strings changed.
func maskReportEmails(report *ctis.Report) int {
	if report == nil {
		return 0
	}
	n := 0
	for i := range report.Findings {
		n += maskFindingEmails(&report.Findings[i])
	}
	return n
}

func maskFindingEmails(f *ctis.Finding) int {
	n := 0
	v := reflect.ValueOf(f).Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		if fd := t.Field(i); fd.IsExported() && !emailMaskSkipped[fd.Name] {
			n += maskEmailValue(v.Field(i), 0)
		}
	}
	for i := range f.EvidenceItems {
		n += maskEvidenceEmails(&f.EvidenceItems[i])
	}
	return n
}

// maskEmailValue masks every plain string reachable from v: struct fields,
// pointers, slices, map values and interface values. Named string types are
// vocabulary (enums) and map keys are names; both are left alone.
func maskEmailValue(v reflect.Value, depth int) int {
	if depth > maxEmailMaskDepth {
		return 0
	}
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			return maskEmailValue(v.Elem(), depth+1)
		}
	case reflect.Struct:
		n, t := 0, v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).IsExported() {
				n += maskEmailValue(v.Field(i), depth+1)
			}
		}
		return n
	case reflect.String:
		if v.Type() == reflect.TypeFor[string]() && v.CanSet() {
			if s := v.String(); s != "" {
				if m := safetext.MaskEmails(s); m != s {
					v.SetString(m)
					return 1
				}
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return 0
		}
		n := 0
		for i := 0; i < v.Len(); i++ {
			n += maskEmailValue(v.Index(i), depth+1)
		}
		return n
	case reflect.Interface:
		if v.IsNil() || !v.CanSet() {
			return 0
		}
		cp := reflect.New(v.Elem().Type()).Elem()
		cp.Set(v.Elem())
		n := maskEmailValue(cp, depth+1)
		if n > 0 {
			v.Set(cp)
		}
		return n
	case reflect.Map:
		if v.IsNil() {
			return 0
		}
		n := 0
		iter := v.MapRange()
		type kv struct{ k, v reflect.Value }
		var updates []kv
		for iter.Next() {
			cp := reflect.New(iter.Value().Type()).Elem()
			cp.Set(iter.Value())
			if c := maskEmailValue(cp, depth+1); c > 0 {
				n += c
				updates = append(updates, kv{iter.Key(), cp})
			}
		}
		for _, u := range updates {
			v.SetMapIndex(u.k, u.v)
		}
		return n
	}
	return 0
}

// textBody reports whether a body of encoding enc is text (a base64 body is
// binary).
func textBody(enc string) bool { return enc == "" || enc == ctis.BodyEncodingText }

// maskEvidenceEmails masks the e-mail addresses in one evidence item's
// strings and moves the offsets that point into them: a marked span (by its
// JSON pointer) and a body match range. A base64 body is binary and left
// alone; the platform's evidence masking decodes a text body and masks it
// before storing it.
func maskEvidenceEmails(it *ctis.EvidenceItem) int {
	offsets := func(ptr string) []*int {
		var out []*int
		// Each offset moves once, even when two members share it.
		add := func(ps ...*int) {
			for _, p := range ps {
				if p != nil && !slices.Contains(out, p) {
					out = append(out, p)
				}
			}
		}
		for i := range it.Sensitive {
			if sp := &it.Sensitive[i]; sp.Pointer == ptr {
				add(sp.Start, sp.End)
			}
		}
		for i := range it.Match {
			m := &it.Match[i]
			if m.Part == ctis.MatchPartBody && "/http/"+m.Location+"/body" == ptr {
				add(m.Start, m.End)
			}
		}
		return out
	}
	n := 0
	mask := func(s *string, ptr string) {
		if *s == "" {
			return
		}
		if m := safetext.MaskEmailsMoving(*s, offsets(ptr)...); m != *s {
			*s = m
			n++
		}
	}
	mask(&it.Label, "/label")
	mask(&it.Text, "/text")
	mask(&it.Command, "/command")
	for i := range it.Extracted {
		mask(&it.Extracted[i], "/extracted/"+strconv.Itoa(i))
	}
	if it.File != nil {
		mask(&it.File.Snippet, "/file/snippet")
	}
	if h := it.HTTP; h != nil {
		if q := h.Request; q != nil {
			mask(&q.URL, "/http/request/url")
			for i := range q.Headers {
				mask(&q.Headers[i].Value, "/http/request/headers/"+strconv.Itoa(i)+"/value")
			}
			if textBody(q.BodyEncoding) {
				mask(&q.Body, "/http/request/body")
			}
		}
		if r := h.Response; r != nil {
			for i := range r.Headers {
				mask(&r.Headers[i].Value, "/http/response/headers/"+strconv.Itoa(i)+"/value")
			}
			if textBody(r.BodyEncoding) {
				mask(&r.Body, "/http/response/body")
			}
		}
	}
	if it.Data != nil {
		n += maskEmailValue(reflect.ValueOf(&it.Data).Elem(), 0)
	}
	return n
}
