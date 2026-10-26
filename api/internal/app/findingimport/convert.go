package findingimport

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"unicode"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"
	"github.com/openctemio/ctis/importer/mapping"

	appimportmapping "github.com/openctemio/openctem/api/internal/app/importmapping"
)

// Upload is one uploaded file: an export of another tool or a ZIP of them.
type Upload struct {
	// Name labels the file in results; it is never used as a path.
	Name string
	// Body is read once, streaming (a ZIP is spooled to a private temporary
	// file because it is read from its end).
	Body io.Reader
	// KnowledgeBase is the Qualys KnowledgeBase companion, when the caller
	// received one separately.
	KnowledgeBase []byte
	// Format forces the format of a single file (empty: detected).
	Format importer.Format
	// Mapping, when set, converts the single file through an organization's
	// import mapping instead of an importer (Format is then its receipt
	// format, "mapping:<name>@<n>").
	Mapping *appimportmapping.Resolved
	// MinSeverity drops findings below it (empty keeps all).
	MinSeverity ctis.Severity
	// ReportIDPrefix names the reports: "<prefix>-<n>". A caller that
	// stores the results replaces it with its own producer id.
	ReportIDPrefix string
	// TempDir is where a ZIP is spooled ("" = os.TempDir()).
	TempDir string
	// NoBundle refuses a ZIP that is a multi-file bundle (a recon
	// directory): set when the request declares full coverage, which a
	// bundle can never prove.
	NoBundle bool
	// Repository, Branch and CommitSHA, when set, are the repository every
	// code report is filed on, whatever the file names (a CI run sets them
	// from its verified token). Records that name no asset go there too.
	Repository string
	Branch     string
	CommitSHA  string
}

// Converted is one file of an upload, converted or refused.
type Converted struct {
	Name   string
	Result *importer.Result
	Error  *FileError
}

// MaxKnowledgeBase bounds a Qualys KnowledgeBase read into memory (the
// parser needs it before the detections).
const MaxKnowledgeBase = 64 << 20

// Error kinds of a FileError.
const (
	KindUnknownFormat = "unknown_format"
	KindTooLarge      = "too_large"
	KindUnsafe        = "unsafe"
	KindMalformed     = "malformed"
	KindFailed        = "failed"
	// KindReadFailed: the upload itself could not be read (the caller
	// knows why: a body limit, a closed connection).
	KindReadFailed = "read_failed"
)

// Convert is the one entry point that turns an upload into CTIS. The format
// is read from the content (importer.IsZip, importer.Detect), never from a
// name or a media type. A ZIP is listed under ArchiveLimits and each of its
// files converted under FileLimits; a Qualys KnowledgeBase inside it is
// paired with its Qualys detection files. each is called once per file, in
// order, so one file's result is released before the next is read.
//
// It returns archive=true for a ZIP, and a FileError when the upload as a
// whole is refused (an unreadable or unsafe archive, a KnowledgeBase alone,
// a forced format on an archive). A single file that cannot be converted is
// reported through each.
func Convert(ctx context.Context, up Upload, each func(Converted)) (archive bool, refused *FileError) {
	br := bufio.NewReaderSize(up.Body, importer.SniffLen)
	head, err := br.Peek(importer.SniffLen)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return false, &FileError{Kind: KindReadFailed, Message: "the upload could not be read"}
	}
	if importer.IsZip(head) {
		if up.Format != "" || up.Mapping != nil {
			return true, &FileError{Kind: KindMalformed, Message: "format applies to a single file, not to an archive"}
		}
		return true, convertArchive(ctx, up, br, each)
	}
	if f, ok := importer.Detect(head); ok && f == importer.FormatQualysKB {
		return false, &FileError{Kind: KindUnknownFormat,
			Message: "a Qualys KnowledgeBase goes in the knowledge_base part, with its detection file"}
	}
	each(convertOne(ctx, up, SafeName(up.Name), br, up.KnowledgeBase, up.Format, 0))
	return false, nil
}

func convertOne(ctx context.Context, up Upload, name string, r io.Reader, kb []byte, format importer.Format, n int) Converted {
	if up.Mapping != nil {
		return convertMapped(ctx, up, name, r, n)
	}
	var kbr io.Reader
	if kb != nil {
		kbr = bytes.NewReader(kb)
	}
	opts := importer.Options{
		Format:              format,
		Limits:              FileLimits,
		ReportID:            fmt.Sprintf("%s-%d", up.ReportIDPrefix, n),
		MinSeverity:         up.MinSeverity,
		QualysKnowledgeBase: kbr,
		Repository:          up.Repository,
		Branch:              up.Branch,
		CommitSHA:           up.CommitSHA,
	}
	if up.Repository != "" {
		opts.DefaultAsset = &ctis.Asset{Type: ctis.AssetTypeRepository, Value: up.Repository}
	}
	res, err := importer.Parse(ctx, r, opts)
	if err != nil {
		return Converted{Name: name, Error: fileError(err)}
	}
	return Converted{Name: name, Result: res}
}

// convertMapped converts one file through an import mapping. The result
// looks like an importer's: the format is the mapping's receipt format, the
// tool is "mapped:<name>" (never a name from the file), and a CI run's
// repository is the asset of every record that names none.
func convertMapped(ctx context.Context, up Upload, name string, r io.Reader, n int) Converted {
	m := up.Mapping
	report, st, err := m.Compiled.Apply(ctx, r, appimportmapping.ApplyOptions(m, FileLimits.MaxInputBytes))
	if err != nil {
		return Converted{Name: name, Error: mappedError(err)}
	}
	report.Metadata.ID = fmt.Sprintf("%s-%d", up.ReportIDPrefix, n)
	report.Metadata.SourceType = "manual"
	// A mapped file never proves what it did not report.
	report.Metadata.CoverageType = "partial"
	res := &importer.Result{
		Format: importer.Format(m.Format()),
		Report: report,
		Stats: importer.Stats{Records: st.Records, Assets: st.Assets, Findings: st.Findings,
			Components: st.Dependencies, Skipped: st.Skipped, BySeverity: map[ctis.Severity]int{}},
	}
	kept := report.Findings[:0]
	for _, f := range report.Findings {
		if up.MinSeverity != "" && f.Severity.Score() < up.MinSeverity.Score() {
			res.Stats.Skipped++
			res.Stats.Findings--
			continue
		}
		if up.Repository != "" && strings.TrimSpace(f.AssetValue) == "" {
			f.AssetType, f.AssetValue = ctis.AssetTypeRepository, up.Repository
		}
		res.Stats.BySeverity[f.Severity]++
		kept = append(kept, f)
	}
	report.Findings = kept
	for _, is := range st.Issues {
		res.Issues = append(res.Issues, importer.Issue{Line: is.Record, Message: is.String()})
	}
	return Converted{Name: name, Result: res}
}

func mappedError(err error) *FileError {
	fe := &FileError{Kind: KindMalformed, Message: err.Error()}
	switch {
	case errors.Is(err, mapping.ErrInputTooLarge), errors.Is(err, importer.ErrTooLarge):
		fe.Kind, fe.Message = KindTooLarge, "the file is larger than the import limit"
	case errors.Is(err, importer.ErrUnsafe):
		fe.Kind = KindUnsafe
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		fe.Kind, fe.Message = KindFailed, "the import took too long"
	}
	if len(fe.Message) > 300 {
		fe.Message = strings.ToValidUTF8(fe.Message[:300], "")
	}
	return fe
}

func convertArchive(ctx context.Context, up Upload, r io.Reader, each func(Converted)) *FileError {
	tmp, err := os.CreateTemp(up.TempDir, "openctem-import-*.zip")
	if err != nil {
		return &FileError{Kind: KindFailed, Message: "the archive could not be stored for reading"}
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	size, err := io.Copy(tmp, r)
	if err != nil {
		return &FileError{Kind: KindReadFailed, Message: "the upload could not be read"}
	}
	if names, ok := zipNames(tmp, size); ok {
		if _, isBundle := importer.DetectBundle(names); isBundle {
			if up.NoBundle {
				return &FileError{Kind: KindMalformed,
					Message: "a recon results directory is partial coverage and cannot be imported with full coverage"}
			}
			return convertBundle(ctx, up, tmp, size, each)
		}
	}
	entries, err := importer.OpenZip(tmp, size, ArchiveLimits)
	if err != nil {
		return archiveError(err)
	}
	if len(entries) == 0 {
		return &FileError{Kind: KindMalformed, Message: "the archive holds no file"}
	}
	label := SafeName(up.Name)

	// First pass: the formats, and the KnowledgeBase.
	kb := up.KnowledgeBase
	formats := make([]importer.Format, len(entries))
	for i, e := range entries {
		f, err := detectEntry(e)
		if err != nil {
			return archiveError(err)
		}
		formats[i] = f
		if f == importer.FormatQualysKB && kb == nil {
			if kb, err = readEntry(e, MaxKnowledgeBase); err != nil {
				return archiveError(err)
			}
		}
	}
	n := 0
	for i, e := range entries {
		if formats[i] == importer.FormatQualysKB {
			continue
		}
		if err := ctx.Err(); err != nil {
			return &FileError{Kind: KindFailed, Message: "the import took too long"}
		}
		rc, err := e.Open()
		if err != nil {
			return archiveError(err)
		}
		var entryKB []byte
		if formats[i] == importer.FormatQualys {
			entryKB = kb
		}
		each(convertOne(ctx, up, label+"/"+SafeName(e.Name), rc, entryKB, "", n))
		_ = rc.Close()
		n++
	}
	return nil
}

// BundleLimits bound a multi-file bundle (a recon directory).
var BundleLimits = importer.DefaultBundleLimits()

// BundleRecordLimits bound the records one bundle may produce.
var BundleRecordLimits = importer.Limits{
	MaxInputBytes: 256 << 20,
	MaxFindings:   200_000,
	MaxAssets:     200_000,
	MaxIssues:     100,
}

// maxBundleNames bounds the names read from an archive's directory before
// the bundle is recognized.
const maxBundleNames = 50_000

// zipNames lists the entry names of a ZIP without reading any entry. ok is
// false when the directory cannot be read or holds too many entries.
func zipNames(r io.ReaderAt, size int64) ([]string, bool) {
	zr, err := zip.NewReader(r, size)
	if err != nil || len(zr.File) > maxBundleNames {
		return nil, false
	}
	names := make([]string, len(zr.File))
	for i, f := range zr.File {
		names[i] = f.Name
	}
	return names, true
}

// convertBundle reads a recon directory as one unit (importer.ParseBundle):
// its files are joined (webs, subdomains, nuclei) into one report, which
// is partial coverage by nature. The result carries the files the importer
// did not read (Skipped on purpose, Unmapped).
func convertBundle(ctx context.Context, up Upload, tmp io.ReaderAt, size int64, each func(Converted)) *FileError {
	files, err := importer.OpenBundleZip(tmp, size, BundleLimits)
	if err != nil {
		return archiveError(err)
	}
	if err := ctx.Err(); err != nil {
		return &FileError{Kind: KindFailed, Message: "the import took too long"}
	}
	res, err := importer.ParseBundle(ctx, files, importer.Options{
		Limits:      BundleRecordLimits,
		Bundle:      BundleLimits,
		ReportID:    fmt.Sprintf("%s-0", up.ReportIDPrefix),
		MinSeverity: up.MinSeverity,
	})
	label := SafeName(up.Name)
	if err != nil {
		each(Converted{Name: label, Error: fileError(err)})
		return nil
	}
	each(Converted{Name: label, Result: res})
	return nil
}

func detectEntry(e importer.ArchiveFile) (importer.Format, error) {
	rc, err := e.Open()
	if err != nil {
		return "", err
	}
	defer func() { _ = rc.Close() }()
	head, err := io.ReadAll(io.LimitReader(rc, importer.SniffLen))
	if err != nil {
		return "", err
	}
	f, _ := importer.Detect(head)
	return f, nil
}

func readEntry(e importer.ArchiveFile, limit int64) ([]byte, error) {
	rc, err := e.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: the knowledge base is too large", importer.ErrTooLarge)
	}
	return b, nil
}

func archiveError(err error) *FileError {
	fe := &FileError{Kind: KindMalformed, Message: "the archive could not be read"}
	var pe *importer.ParseError
	if errors.As(err, &pe) {
		fe.Message = pe.Error()
	}
	switch {
	case errors.Is(err, importer.ErrUnsafe):
		fe.Kind = KindUnsafe
	case errors.Is(err, importer.ErrTooLarge):
		fe.Kind = KindTooLarge
	}
	return fe
}

// SafeName keeps a client file name as a label only: the base name,
// printable, at most 200 characters. It is never used as a path.
func SafeName(s string) string {
	s = path.Base(strings.ReplaceAll(s, "\\", "/"))
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200])
	}
	if s == "" || s == "." || s == "/" {
		return "upload"
	}
	return s
}
