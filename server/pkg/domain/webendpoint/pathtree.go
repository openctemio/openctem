package webendpoint

import (
	"errors"
	"path"
	"slices"
	"strings"
	"unicode"

	"github.com/openctemio/ctis/v2/weburl"
)

// The path tree of one origin (docs/architecture/web-surface.md, "Path
// tree"): the origin's endpoints folded into folders by path segment, one
// level at a time, with the open findings whose URL lies under each folder.
// Everything here is computed from rows of one tenant's one origin that the
// caller may see; nothing is stored.

const (
	// PathLoadLimit bounds the endpoint rows one tree request reads: the
	// active cap plus room for gone and ignored rows kept by retention.
	PathLoadLimit = 4 * MaxActivePerOrigin
	// MaxPathFolders bounds the folders of one level in a response.
	MaxPathFolders = 500
	// MaxPathPerPage bounds the endpoint page of one response.
	MaxPathPerPage = 100
	// MaxPathSearchBytes bounds the path search text.
	MaxPathSearchBytes = 200
	// MaxPathFindingRows bounds the finding groups one request reads.
	MaxPathFindingRows = 20000
)

// ErrInvalidPathQuery is a malformed tree request.
var ErrInvalidPathQuery = errors.New("invalid path tree query")

// Scope filter values of a path query.
const (
	PathScopeAny = ""
	PathScopeIn  = "in"
	PathScopeOut = "out"
)

// PathQuery selects one level of an origin's path tree.
type PathQuery struct {
	// Path is the node: "/" or a path template without a trailing slash. A
	// node holds the endpoints of its own template and of every template
	// below it.
	Path string
	// Search keeps endpoints whose template contains it (any case).
	Search string
	// HideStatic hides style sheets, images, fonts, media and archives.
	HideStatic bool
	// Hide4xx hides endpoints whose last answer was 400-499.
	Hide4xx bool
	// WithFindings keeps endpoints with at least one open finding at their path.
	WithFindings bool
	// IncludeGone also shows endpoints not seen for 30 days.
	IncludeGone bool
	// Scope is PathScopeAny, PathScopeIn or PathScopeOut.
	Scope string
	// Methods keeps these methods (none: all).
	Methods []string
	// Here lists only the endpoints of the node's own template, not those
	// below it.
	Here bool
	// Page is 1-based; PerPage 0 returns the folders without endpoints.
	Page, PerPage int
	// Findings also lists the open findings at the node's own template
	// (with Here only).
	Findings bool
}

// Validate normalises the query and refuses a malformed one.
func (q *PathQuery) Validate() error {
	if q.Path == "" {
		q.Path = "/"
	}
	if len(q.Path) > MaxPathBytes || q.Path[0] != '/' || (q.Path != "/" && strings.HasSuffix(q.Path, "/")) ||
		strings.Contains(q.Path, "//") || strings.ContainsAny(q.Path, "?#\\") || hasControl(q.Path) {
		return ErrInvalidPathQuery
	}
	q.Search = strings.TrimSpace(q.Search)
	if len(q.Search) > MaxPathSearchBytes || hasControl(q.Search) {
		return ErrInvalidPathQuery
	}
	switch q.Scope {
	case PathScopeAny, PathScopeIn, PathScopeOut:
	default:
		return ErrInvalidPathQuery
	}
	for i, m := range q.Methods {
		n, ok := weburl.NormalizeMethod(m)
		if !ok {
			return ErrInvalidPathQuery
		}
		q.Methods[i] = n
	}
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PerPage < 0 || q.PerPage > MaxPathPerPage || (q.Findings && !q.Here) {
		return ErrInvalidPathQuery
	}
	return nil
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}

// PathFinding is a group of open findings of the origin asset with one
// location key and one severity.
type PathFinding struct {
	LocationKey string
	Severity    string
	Count       int
	// Template and Method are the path template and method of the endpoint
	// the finding is linked to (finding_web_locations.endpoint_id); both ""
	// for a finding with no link, which the location key maps instead.
	Template string
	Method   string
}

// MaxNodeFindings bounds the findings listed for one node.
const MaxNodeFindings = 50

// NodeFinding is an open finding of the origin whose URL lies at a node's
// own template. Path is the finding's concrete path masked like an example
// path (tokens, digests and opaque ids replaced by their variable).
type NodeFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Path     string `json:"path"`
	// Method is the HTTP method of the endpoint the finding is linked to.
	Method string `json:"method,omitempty"`
}

// FindingRow is an open finding of the origin with a URL location, read to
// list a node's findings.
type FindingRow struct {
	ID, Title, Severity, Status, LocationKey string
	// Template and Method: the linked endpoint, "" when the finding has none.
	Template, Method string
}

// NodeFindings keeps the rows whose URL templates to node on originURL's
// origin, most severe first, at most MaxNodeFindings, and the total.
func NodeFindings(rows []FindingRow, originURL, node string) ([]NodeFinding, int) {
	want := ""
	if o, err := weburl.Parse(originURL); err == nil {
		want = o.Origin()
	}
	out := make([]NodeFinding, 0, 8)
	for _, r := range rows {
		if r.Template != "" { // the exact link: the endpoint's own template
			if r.Template == node {
				out = append(out, NodeFinding{ID: r.ID, Title: r.Title, Severity: r.Severity, Status: r.Status,
					Path: linkedPath(r), Method: r.Method})
			}
			continue
		}
		raw, ok := strings.CutPrefix(r.LocationKey, "url:")
		if !ok {
			continue
		}
		u, err := weburl.Parse(raw)
		if err != nil || u.Template() != node || (want != "" && u.Origin() != want) {
			continue
		}
		out = append(out, NodeFinding{ID: r.ID, Title: r.Title, Severity: r.Severity, Status: r.Status, Path: MaskPath(u.Path)})
	}
	slices.SortStableFunc(out, func(a, b NodeFinding) int { return severityRank[b.Severity] - severityRank[a.Severity] })
	total := len(out)
	if total > MaxNodeFindings {
		out = out[:MaxNodeFindings]
	}
	return out, total
}

// linkedPath is the path shown for a linked finding: its URL's path when the
// location key holds one, else the endpoint's template.
func linkedPath(r FindingRow) string {
	if raw, ok := strings.CutPrefix(r.LocationKey, "url:"); ok {
		if u, err := weburl.Parse(raw); err == nil {
			return MaskPath(u.Path)
		}
	}
	return r.Template
}

// PathFolder is one sub-folder of the requested level, with what lies under
// it after the filters.
type PathFolder struct {
	Name string `json:"name"`
	Path string `json:"path"`
	// Param marks a variable segment ({int}, {uuid}, ...).
	Param      bool `json:"param"`
	Endpoints  int  `json:"endpoints"`
	OutOfScope int  `json:"out_of_scope"`
	Findings   int  `json:"findings"`
	// TopSeverity is the most severe open finding under the folder, or "".
	TopSeverity string `json:"top_severity,omitempty"`
	// HasFolders tells whether the folder has sub-folders of its own.
	HasFolders bool `json:"has_folders"`
}

// PathEndpoint is an endpoint of the level with the open findings at its
// path template (a finding linked to an endpoint counts at that method only; one with no link counts at every method of the template).
type PathEndpoint struct {
	Endpoint    *Endpoint
	Findings    int
	TopSeverity string
}

// PathTotals describes the level as a whole.
type PathTotals struct {
	// Recorded counts every endpoint row of the origin, before any filter:
	// 0 means the site was never crawled.
	Recorded int `json:"recorded"`
	// Endpoints under the node that pass the filters, and those the
	// filters hide.
	Endpoints int `json:"endpoints"`
	Hidden    int `json:"hidden"`
	// OutOfScope counts the shown endpoints under a path exclusion.
	OutOfScope int `json:"out_of_scope"`
	// Findings under the node: at shown endpoints and at paths no endpoint
	// records (Unrecorded).
	Findings    int    `json:"findings"`
	Unrecorded  int    `json:"unrecorded_findings"`
	TopSeverity string `json:"top_severity,omitempty"`
	// OriginFindings are open findings of the origin with no path on it (no
	// URL, or a URL of another origin). Reported at the root only.
	OriginFindings int `json:"origin_findings"`
	// Capped is true when the origin had more rows than one request reads.
	Capped bool `json:"capped"`
}

// PathLevel is one level of the tree.
type PathLevel struct {
	Path             string
	Folders          []PathFolder
	FoldersTruncated bool
	Endpoints        []PathEndpoint
	EndpointTotal    int
	Totals           PathTotals
	// NodeFindings and NodeFindingTotal: the findings at the node's own
	// template, when the query asked for them.
	NodeFindings     []NodeFinding
	NodeFindingTotal int
}

// Finding severities, worst first.
const (
	sevCritical = "critical"
	sevHigh     = "high"
	sevMedium   = "medium"
	sevLow      = "low"
	sevInfo     = "info"
)

var severityRank = map[string]int{sevCritical: 5, sevHigh: 4, sevMedium: 3, sevLow: 2, sevInfo: 1}

func worse(a, b string) string {
	if severityRank[b] > severityRank[a] {
		return b
	}
	return a
}

// staticTypes are content type prefixes of static files.
var staticTypes = []string{"image/", "font/", "audio/", "video/", "text/css", "application/octet-stream",
	"application/font", "application/x-font", "application/vnd.ms-fontobject", "application/pdf",
	"application/zip", "application/gzip", "application/x-gzip", "application/x-tar", "application/x-7z",
	"application/x-rar"}

// staticExts are file extensions (without the dot) of static files. Scripts and source maps
// are not static here: they are attack surface.
var staticExts = func() map[string]bool {
	m := map[string]bool{}
	for _, e := range strings.Fields(`css png jpg jpeg gif svg ico webp bmp avif tif tiff woff woff2 ttf otf eot
		mp4 webm mp3 wav ogg pdf zip gz tgz tar rar 7z exe dmg iso bin`) {
		m[e] = true
	}
	return m
}()

// IsStatic reports whether an endpoint serves a style sheet, an image, a
// font, media or a binary, by its content type or its file extension.
func IsStatic(e *Endpoint) bool {
	ct := strings.ToLower(e.ContentType)
	for _, p := range staticTypes {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return staticExts[strings.TrimPrefix(strings.ToLower(path.Ext(e.PathTemplate)), ".")]
}

func (q *PathQuery) keeps(e *Endpoint, findings int) bool {
	switch {
	case !q.IncludeGone && e.State == StateGone,
		q.HideStatic && IsStatic(e),
		q.Hide4xx && e.LastStatus >= 400 && e.LastStatus <= 499,
		q.Scope == PathScopeIn && !e.InScope,
		q.Scope == PathScopeOut && e.InScope,
		len(q.Methods) > 0 && !slices.Contains(q.Methods, e.Method),
		q.WithFindings && findings == 0:
		return false
	}
	return true
}

func matchesSearch(template, search string) bool {
	return search == "" || strings.Contains(strings.ToLower(template), strings.ToLower(search))
}

// pathFindings are the findings mapped onto path templates.
type pathFindings struct {
	byTemplate map[string]int // every finding at a template: linked and mapped
	topByTmpl  map[string]string
	// The two kinds apart. A finding linked to an endpoint counts at that
	// endpoint (template and method) only; one with no link is mapped by its
	// URL and is method-blind, so it counts at every method of the template.
	linked      map[epKey]int
	linkedTop   map[epKey]string
	unlinked    map[string]int
	unlinkedTop map[string]string
	origin      int
}

type epKey struct{ template, method string }

// at is what an endpoint shows: the findings linked to it plus those mapped
// onto its template by URL.
func (pf pathFindings) at(e *Endpoint) (int, string) {
	k := epKey{e.PathTemplate, e.Method}
	return pf.linked[k] + pf.unlinked[e.PathTemplate], worse(pf.linkedTop[k], pf.unlinkedTop[e.PathTemplate])
}

// mapFindings maps each finding's URL onto a path template with the same
// templating the endpoints use (exact on the path, method-blind). A finding
// with no URL, or a URL of another origin, belongs to the origin as a whole.
// originURL is the origin asset's name; when it is not a web origin the
// finding's own origin is not compared.
func mapFindings(fs []PathFinding, originURL string) pathFindings {
	out := pathFindings{byTemplate: map[string]int{}, topByTmpl: map[string]string{}, linked: map[epKey]int{},
		linkedTop: map[epKey]string{}, unlinked: map[string]int{}, unlinkedTop: map[string]string{}}
	want := ""
	if o, err := weburl.Parse(originURL); err == nil {
		want = o.Origin()
	}
	for _, f := range fs {
		if f.Template != "" { // linked to an endpoint of the origin: exact
			k := epKey{f.Template, f.Method}
			out.linked[k] += f.Count
			out.linkedTop[k] = worse(out.linkedTop[k], f.Severity)
			out.byTemplate[f.Template] += f.Count
			out.topByTmpl[f.Template] = worse(out.topByTmpl[f.Template], f.Severity)
			continue
		}
		raw, ok := strings.CutPrefix(f.LocationKey, "url:")
		if !ok {
			out.origin += f.Count
			continue
		}
		origin, tmpl, _, err := weburl.Template(raw)
		if err != nil || tmpl == "" || (want != "" && origin != want) {
			out.origin += f.Count
			continue
		}
		out.byTemplate[tmpl] += f.Count
		out.topByTmpl[tmpl] = worse(out.topByTmpl[tmpl], f.Severity)
		out.unlinked[tmpl] += f.Count
		out.unlinkedTop[tmpl] = worse(out.unlinkedTop[tmpl], f.Severity)
	}
	return out
}

type folderAcc struct {
	PathFolder
	templates map[string]bool
}

// childOf places a template relative to the node: seg is the child node it
// lies in ("" when the template is the node itself), deeper tells whether it
// lies below that child, and ok is false when it is not under the node.
func childOf(template, node string) (seg string, deeper, ok bool) {
	if template == node {
		return "", false, true
	}
	base := node
	if node == "/" {
		base = ""
	}
	rest, under := strings.CutPrefix(template, base+"/")
	if !under || rest == "" {
		return "", false, false
	}
	seg, _, deeper = strings.Cut(rest, "/")
	return seg, deeper, true
}

// childPath is the node path of seg under node.
func childPath(node, seg string) string {
	if node == "/" {
		return "/" + seg
	}
	return node + "/" + seg
}

// BuildPathLevel computes one level of the tree from the origin's endpoint
// rows and its open findings. eps must all belong to one origin of one
// tenant the caller may see.
func BuildPathLevel(eps []*Endpoint, fs []PathFinding, originURL string, capped bool, q PathQuery) PathLevel {
	pf := mapFindings(fs, originURL)
	lvl := PathLevel{Path: q.Path, Totals: PathTotals{Recorded: len(eps), Capped: capped}}
	if q.Path == "/" {
		lvl.Totals.OriginFindings = pf.origin
	}
	folders := map[string]*folderAcc{}
	folder := func(seg string) *folderAcc {
		f := folders[seg]
		if f == nil {
			f = &folderAcc{PathFolder: PathFolder{Name: seg, Path: childPath(q.Path, seg),
				Param: strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")}, templates: map[string]bool{}}
			folders[seg] = f
		}
		return f
	}
	recorded := make(map[string]bool, len(eps))
	counted := map[string]bool{} // templates whose findings are already in the totals
	addFindings := func(tmpl string, acc *folderAcc) {
		n := pf.byTemplate[tmpl]
		if n == 0 {
			return
		}
		if acc != nil && !acc.templates[tmpl] {
			acc.templates[tmpl] = true
			acc.Findings += n
			acc.TopSeverity = worse(acc.TopSeverity, pf.topByTmpl[tmpl])
		}
		if !counted[tmpl] {
			counted[tmpl] = true
			lvl.Totals.Findings += n
			lvl.Totals.TopSeverity = worse(lvl.Totals.TopSeverity, pf.topByTmpl[tmpl])
		}
	}
	shown := make([]PathEndpoint, 0, 64)
	for _, e := range eps {
		recorded[e.PathTemplate] = true
		seg, deeper, under := childOf(e.PathTemplate, q.Path)
		if !under || !matchesSearch(e.PathTemplate, q.Search) {
			continue
		}
		n, top := pf.at(e)
		if !q.keeps(e, n) {
			lvl.Totals.Hidden++
			continue
		}
		lvl.Totals.Endpoints++
		if !e.InScope {
			lvl.Totals.OutOfScope++
		}
		var acc *folderAcc
		if seg != "" {
			acc = folder(seg)
			acc.Endpoints++
			if !e.InScope {
				acc.OutOfScope++
			}
			acc.HasFolders = acc.HasFolders || deeper
		}
		addFindings(e.PathTemplate, acc)
		if seg == "" || !q.Here {
			shown = append(shown, PathEndpoint{Endpoint: e, Findings: n, TopSeverity: top})
		}
	}
	// Findings at paths no endpoint records still sit in their folders: a
	// scanner can hit a path a crawl never listed.
	for tmpl, n := range pf.byTemplate {
		if recorded[tmpl] || !matchesSearch(tmpl, q.Search) {
			continue
		}
		seg, deeper, under := childOf(tmpl, q.Path)
		if !under {
			continue
		}
		lvl.Totals.Unrecorded += n
		var acc *folderAcc
		if seg != "" {
			acc = folder(seg)
			acc.HasFolders = acc.HasFolders || deeper
		}
		addFindings(tmpl, acc)
	}
	lvl.Folders = make([]PathFolder, 0, len(folders))
	for _, f := range folders {
		lvl.Folders = append(lvl.Folders, f.PathFolder)
	}
	slices.SortFunc(lvl.Folders, func(a, b PathFolder) int {
		if a.Param != b.Param { // variable segments after named ones
			if a.Param {
				return 1
			}
			return -1
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	if len(lvl.Folders) > MaxPathFolders {
		lvl.Folders, lvl.FoldersTruncated = lvl.Folders[:MaxPathFolders], true
	}
	slices.SortFunc(shown, func(a, b PathEndpoint) int {
		if c := strings.Compare(a.Endpoint.PathTemplate, b.Endpoint.PathTemplate); c != 0 {
			return c
		}
		return strings.Compare(a.Endpoint.Method, b.Endpoint.Method)
	})
	lvl.EndpointTotal = len(shown)
	if q.PerPage > 0 {
		from := min((q.Page-1)*q.PerPage, len(shown))
		to := min(from+q.PerPage, len(shown))
		lvl.Endpoints = shown[from:to]
	}
	return lvl
}
