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

// Info describes a valid template.
type Info struct {
	Tags     []string // distinct tags in the template, sorted
	Warnings []string // non-fatal problems (literal braces, unknown paths)
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
	entries, err := readPackage(data)
	if err != nil {
		return nil, err
	}
	info := &Info{}
	tags := map[string]bool{}
	for _, e := range entries {
		if !templateParts.MatchString(e.name) {
			continue
		}
		root, err := parseXML(string(e.data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.name, err)
		}
		found, warnings, err := prepare(root)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.name, err)
		}
		for _, t := range found {
			tags[t.String()] = true
		}
		info.Warnings = append(info.Warnings, warnings...)
	}
	for t := range tags {
		info.Tags = append(info.Tags, t)
	}
	sort.Strings(info.Tags)
	return info, nil
}

// Render fills the template with data and returns the new .docx. In strict
// mode the returned Info lists tag paths the data does not have, which a
// preview with sample data reports as warnings.
func Render(template []byte, data Data, strict bool) ([]byte, *Info, error) {
	entries, err := readPackage(template)
	if err != nil {
		return nil, nil, err
	}
	info := &Info{}
	r := &renderer{maxOut: MaxOutputBytes, strict: strict, missing: map[string]bool{}}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, e := range entries {
		content := e.data
		if templateParts.MatchString(e.name) {
			root, err := parseXML(string(e.data))
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", e.name, err)
			}
			_, warnings, err := prepare(root)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", e.name, err)
			}
			info.Warnings = append(info.Warnings, warnings...)
			r.out.Reset()
			if err := r.renderChildren(root, []any{data}); err != nil {
				return nil, nil, err
			}
			rendered := r.out.String()
			if err := wellFormed(rendered); err != nil {
				return nil, nil, fmt.Errorf("%w: %s renders invalid XML; check that sections open and close around whole paragraphs or rows", ErrInvalidTemplate, e.name)
			}
			content = []byte(rendered)
		}
		method := e.method
		if method != zip.Store {
			method = zip.Deflate
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: method})
		if err != nil {
			return nil, nil, fmt.Errorf("write report: %w", err)
		}
		if _, err := w.Write(content); err != nil {
			return nil, nil, fmt.Errorf("write report: %w", err)
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
