// Package docx renders organization-supplied Word (.docx) report templates
// with a small, fixed tag language (see tags.go) over a data map. Templates
// are untrusted input: there is no expression language, no function call, no
// URL fetching, and every size is bounded. Design: api/docs/rfcs/RFC-076-pentest-report-templates.md.
package docx

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/report/markdown"
)

var (
	// ErrInvalidTemplate: the file is not an acceptable template. The message
	// says why, for the template author.
	ErrInvalidTemplate = errors.New("invalid report template")
	// ErrOutputTooLarge: rendering exceeded the output bounds.
	ErrOutputTooLarge = errors.New("rendered report is too large")
)

// Limits bound what a template may be and what a render may produce.
const (
	MaxTemplateBytes = 10 << 20 // uploaded file
	maxEntries       = 300
	maxEntryBytes    = 20 << 20 // one decompressed entry
	maxTotalBytes    = 60 << 20 // all decompressed entries
	MaxOutputBytes   = 50 << 20 // one rendered document part
)

const (
	contentTypeDocument = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
	contentTypeTemplate = "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml"
)

// templateParts are the parts tags are read from: body, headers, footers,
// footnotes and endnotes.
var templateParts = regexp.MustCompile(`^word/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$`)

// Info describes a template.
type Info struct {
	Tags     []string // distinct tags in the template, sorted
	Issues   []Issue  // every problem found, errors and warnings, in document order per part
	Warnings []string // the messages of the warning issues
}

// HasErrors reports whether an issue makes the template unusable.
func (i *Info) HasErrors() bool {
	for _, is := range i.Issues {
		if is.Level == LevelError {
			return true
		}
	}
	return false
}

func (i *Info) addIssues(issues []Issue) {
	i.Issues = append(i.Issues, issues...)
	for _, is := range issues {
		if is.Level == LevelWarning {
			i.Warnings = append(i.Warnings, is.Message)
		}
	}
}

type entry struct {
	name   string
	method uint16
	data   []byte
}

// readPackage opens the zip within the limits and runs the package checks:
// a Word document (not macro-enabled), no macros, ActiveX or embedded
// objects, and no external relationship other than a hyperlink.
func readPackage(data []byte) ([]entry, error) {
	if len(data) == 0 || len(data) > MaxTemplateBytes {
		return nil, fmt.Errorf("%w: the file must be between 1 byte and %d MiB", ErrInvalidTemplate, MaxTemplateBytes>>20)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("%w: not a .docx file", ErrInvalidTemplate)
	}
	if len(zr.File) > maxEntries {
		return nil, fmt.Errorf("%w: the file has more than %d parts", ErrInvalidTemplate, maxEntries)
	}
	seen := map[string]bool{}
	entries := make([]entry, 0, len(zr.File))
	var total int64
	for _, f := range zr.File {
		name := f.Name
		if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") ||
			strings.Contains(name, "..") || path.Clean(name) != name && !strings.HasSuffix(name, "/") {
			return nil, fmt.Errorf("%w: unsafe part name", ErrInvalidTemplate)
		}
		lower := strings.ToLower(name)
		if seen[lower] {
			return nil, fmt.Errorf("%w: duplicate part %q", ErrInvalidTemplate, name)
		}
		seen[lower] = true
		if strings.HasSuffix(lower, "vbaproject.bin") || strings.HasPrefix(lower, "word/activex/") ||
			strings.HasPrefix(lower, "word/embeddings/") || strings.HasSuffix(lower, "vbadata.xml") {
			return nil, fmt.Errorf("%w: macros, ActiveX controls and embedded objects are not allowed", ErrInvalidTemplate)
		}
		if f.UncompressedSize64 > maxEntryBytes {
			return nil, fmt.Errorf("%w: a part is larger than %d MiB", ErrInvalidTemplate, maxEntryBytes>>20)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("%w: unreadable part", ErrInvalidTemplate)
		}
		// Read at most the limit + 1 byte: the declared size is not trusted.
		buf, err := io.ReadAll(io.LimitReader(rc, maxEntryBytes+1))
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("%w: unreadable part", ErrInvalidTemplate)
		}
		if len(buf) > maxEntryBytes {
			return nil, fmt.Errorf("%w: a part is larger than %d MiB", ErrInvalidTemplate, maxEntryBytes>>20)
		}
		total += int64(len(buf))
		if total > maxTotalBytes {
			return nil, fmt.Errorf("%w: the file expands to more than %d MiB", ErrInvalidTemplate, maxTotalBytes>>20)
		}
		entries = append(entries, entry{name: name, method: f.Method, data: buf})
	}
	if err := checkContentTypes(entries); err != nil {
		return nil, err
	}
	if err := checkRelationships(entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func find(entries []entry, name string) *entry {
	for i := range entries {
		if entries[i].name == name {
			return &entries[i]
		}
	}
	return nil
}

type ctTypes struct {
	Overrides []struct {
		PartName    string `xml:"PartName,attr"`
		ContentType string `xml:"ContentType,attr"`
	} `xml:"Override"`
	Defaults []struct {
		Extension   string `xml:"Extension,attr"`
		ContentType string `xml:"ContentType,attr"`
	} `xml:"Default"`
}

func checkContentTypes(entries []entry) error {
	ct := find(entries, "[Content_Types].xml")
	if ct == nil || find(entries, "word/document.xml") == nil {
		return fmt.Errorf("%w: not a Word document", ErrInvalidTemplate)
	}
	var types ctTypes
	if err := decodeStrict(ct.data, &types); err != nil {
		return fmt.Errorf("%w: unreadable content types", ErrInvalidTemplate)
	}
	main := ""
	for _, o := range types.Overrides {
		if strings.Contains(strings.ToLower(o.ContentType), "macroenabled") || strings.Contains(strings.ToLower(o.ContentType), "vba") {
			return fmt.Errorf("%w: macro-enabled documents are not allowed", ErrInvalidTemplate)
		}
		if o.PartName == "/word/document.xml" {
			main = o.ContentType
		}
	}
	for _, d := range types.Defaults {
		if strings.Contains(strings.ToLower(d.ContentType), "macroenabled") || strings.Contains(strings.ToLower(d.ContentType), "vba") {
			return fmt.Errorf("%w: macro-enabled documents are not allowed", ErrInvalidTemplate)
		}
	}
	if main != contentTypeDocument && main != contentTypeTemplate {
		return fmt.Errorf("%w: not a Word document", ErrInvalidTemplate)
	}
	return nil
}

type relationships struct {
	Rels []struct {
		Type       string `xml:"Type,attr"`
		Target     string `xml:"Target,attr"`
		TargetMode string `xml:"TargetMode,attr"`
	} `xml:"Relationship"`
}

// checkRelationships refuses external targets other than hyperlinks: an
// attached template, linked image, OLE link or frame pointing outside the
// file would make Word fetch a URL when the report is opened.
func checkRelationships(entries []entry) error {
	for _, e := range entries {
		if !strings.HasSuffix(e.name, ".rels") {
			continue
		}
		var rels relationships
		if err := decodeStrict(e.data, &rels); err != nil {
			return fmt.Errorf("%w: unreadable relationships", ErrInvalidTemplate)
		}
		for _, r := range rels.Rels {
			if !strings.EqualFold(r.TargetMode, "External") {
				continue
			}
			if !strings.HasSuffix(r.Type, "/hyperlink") {
				return fmt.Errorf("%w: external links other than hyperlinks (linked images, attached templates, frames, OLE links) are not allowed", ErrInvalidTemplate)
			}
		}
	}
	return nil
}

// decodeStrict decodes XML refusing DOCTYPE/ENTITY declarations.
func decodeStrict(data []byte, v any) error {
	if bytes.Contains(bytes.ToUpper(data), []byte("<!DOCTYPE")) || bytes.Contains(bytes.ToUpper(data), []byte("<!ENTITY")) {
		return errors.New("doctype not allowed")
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true
	return d.Decode(v)
}

// wellFormed checks that a rendered part is well-formed XML.
func wellFormed(data string) error {
	d := xml.NewDecoder(strings.NewReader(data))
	d.Strict = true
	for {
		_, err := d.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Inspect validates a template: the package checks, then every tag part
// must parse and its tags must form valid sections. It renders nothing.
func Inspect(data []byte) (*Info, error) {
	return Check(data, nil)
}

// Check is Inspect that also checks every tag path against the data the
// template will read (nil: no path check). The package checks stop at the
// first problem (the file is refused as a whole); tag problems are all
// collected. When any issue is an error, it returns the Info with every
// issue and an ErrInvalidTemplate error naming the first one.
func Check(data []byte, schema *Schema) (*Info, error) {
	entries, err := readPackage(data)
	if err != nil {
		return nil, err
	}
	info := &Info{}
	tags := map[string]bool{}
	var firstErr error
	for _, e := range entries {
		if !templateParts.MatchString(e.name) {
			continue
		}
		c := newChecker(e.name, schema)
		root, err := parseXML(string(e.data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.name, err)
		}
		for _, t := range prepare(root, c) {
			tags[t.String()] = true
		}
		info.addIssues(c.issues)
		if firstErr == nil {
			firstErr = c.firstError()
		}
	}
	for t := range tags {
		info.Tags = append(info.Tags, t)
	}
	sort.Strings(info.Tags)
	if firstErr != nil {
		return info, firstErr
	}
	return info, nil
}

// Render fills the template with data and returns the new .docx. In strict
// mode the returned Info lists tag paths the data does not have, which a
// preview with sample data reports as warnings.
func Render(template []byte, data Data, strict bool) ([]byte, *Info, error) {
	return RenderWithImages(template, data, nil, strict)
}

// RenderWithImages is Render with the evidence images Markdown values may
// embed (keyed by the URL the Markdown cites). Images are embedded in the
// document body only; headers and footers show the alt text.
func RenderWithImages(template []byte, data Data, images map[string]markdown.Image, strict bool) ([]byte, *Info, error) {
	entries, err := readPackage(template)
	if err != nil {
		return nil, nil, err
	}
	info := &Info{}
	r := &renderer{maxOut: MaxOutputBytes, strict: strict, missing: map[string]bool{}}
	sink := newMediaSink(images)
	rendered := map[string][]byte{}
	for _, e := range entries {
		if !templateParts.MatchString(e.name) {
			continue
		}
		root, err := parseXML(string(e.data))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", e.name, err)
		}
		c := newChecker(e.name, nil)
		prepare(root, c)
		if err := c.firstError(); err != nil {
			return nil, nil, err
		}
		info.addIssues(c.issues)
		r.out.Reset()
		r.media = nil
		if e.name == "word/document.xml" {
			r.media = sink
		}
		if err := r.renderChildren(root, []any{data}); err != nil {
			return nil, nil, err
		}
		out := r.out.String()
		if err := wellFormed(out); err != nil {
			return nil, nil, fmt.Errorf("%w: %s renders invalid XML; check that sections open and close around whole paragraphs or rows", ErrInvalidTemplate, e.name)
		}
		rendered[e.name] = []byte(out)
	}

	var media []mediaFile
	if sink != nil {
		media = sink.used
	}
	extra, err := packageMedia(entries, rendered, media)
	if err != nil {
		return nil, nil, err
	}

	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	write := func(name string, method uint16, content []byte) error {
		if method != zip.Store {
			method = zip.Deflate
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method})
		if err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		if _, err := w.Write(content); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		return nil
	}
	for _, e := range entries {
		content := e.data
		if c, ok := rendered[e.name]; ok {
			content = c
		}
		if err := write(e.name, e.method, content); err != nil {
			return nil, nil, err
		}
	}
	for _, x := range extra {
		if err := write(x.name, zip.Deflate, x.data); err != nil {
			return nil, nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, nil, fmt.Errorf("write report: %w", err)
	}
	for _, p := range r.missingPaths() {
		info.Warnings = append(info.Warnings, fmt.Sprintf("{%s} is not in the report data and renders empty", p))
	}
	return out.Bytes(), info, nil
}

type newPart struct {
	name string
	data []byte
}

// packageMedia adds the embedded images to the package: the media parts,
// their relationships from the document (creating the relationships part
// when the template has none) and the image content types. It edits the
// rendered map in place for parts it changes and returns parts to append.
func packageMedia(entries []entry, rendered map[string][]byte, media []mediaFile) ([]newPart, error) {
	if len(media) == 0 {
		return nil, nil
	}
	const relsName = "word/_rels/document.xml.rels"
	extra := make([]newPart, 0, len(media)+1)
	var rels strings.Builder
	exts := map[string]bool{}
	for _, m := range media {
		extra = append(extra, newPart{name: "word/media/" + m.name, data: m.img.Data})
		rels.WriteString(`<Relationship Id="` + m.relID + `" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/` + m.name + `"/>`)
		exts[m.ext] = true
	}
	if rel := find(entries, relsName); rel != nil {
		s := string(rel.data)
		i := strings.LastIndex(s, "</Relationships>")
		if i < 0 {
			return nil, fmt.Errorf("%w: unreadable document relationships", ErrInvalidTemplate)
		}
		rendered[relsName] = []byte(s[:i] + rels.String() + s[i:])
	} else {
		extra = append(extra, newPart{name: relsName, data: []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + rels.String() + `</Relationships>`)})
	}
	ct := find(entries, "[Content_Types].xml")
	s := string(ct.data)
	var defaults strings.Builder
	for _, ext := range []string{"png", "jpeg", "gif"} {
		if exts[ext] && !strings.Contains(strings.ToLower(s), `extension="`+ext+`"`) {
			defaults.WriteString(`<Default Extension="` + ext + `" ContentType="image/` + ext + `"/>`)
		}
	}
	if defaults.Len() > 0 {
		i := strings.LastIndex(s, "</Types>")
		if i < 0 {
			return nil, fmt.Errorf("%w: unreadable content types", ErrInvalidTemplate)
		}
		rendered["[Content_Types].xml"] = []byte(s[:i] + defaults.String() + s[i:])
	}
	return extra, nil
}
