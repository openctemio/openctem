package main

// The versions manifest (openctem-versions.json) is the release summary for
// readers outside an instance: the documentation site, the website and
// install scripts. It is built in the same Release Feed run as the instance
// feed, from the same feed payload, and signed by the same workflow identity,
// so a release changes it without a commit anywhere
// (server/docs/architecture/versions-manifest.md).
//
//	go run ./cmd/release-feed platform -feed feed.json            # the platform release it describes
//	go run ./cmd/release-feed manifest -feed feed.json -images openctem-images-vX.Y.Z.txt \
//	    -versions versions.yaml -compat compat.json -chart-index index.yaml -out openctem-versions.json
//
// A release is withdrawn from both files by marking it a pre-release on
// GitHub and re-running the Release Feed workflow: neither file lists a
// draft or a pre-release.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/server/internal/versions"
	"github.com/openctemio/openctem/server/pkg/feedsign"
	"github.com/openctemio/openctem/server/pkg/releasefeed"
)

// ManifestSchema names the format. A reader refuses another schema; a
// change that removes or renames a field is a new schema version.
const (
	ManifestSchema   = "openctem.io/versions/v1"
	ManifestFileName = "openctem-versions.json"
	// ChartName is the platform chart in the Helm repository.
	ChartName    = "openctem"
	ChartRepoURL = "https://openctemio.github.io/helm-charts"
	// UpgradeDocs is where the upgrade guide of every release lives.
	UpgradeDocs = "https://docs.openctem.io/operations/upgrade/"
)

// Manifest is openctem-versions.json.
type Manifest struct {
	Schema      string                 `json:"schema"`
	GeneratedAt time.Time              `json:"generated_at"`
	Platform    ManifestPlatform       `json:"platform"`
	Components  []ManifestComponent    `json:"components"`
	Chart       ManifestChart          `json:"chart"`
	Advisories  []releasefeed.Advisory `json:"advisories"`
}

// ManifestPlatform is the newest stable platform release.
type ManifestPlatform struct {
	Version     string          `json:"version"`
	PublishedAt time.Time       `json:"published_at"`
	NotesURL    string          `json:"notes_url"`
	UpgradeURL  string          `json:"upgrade_url"`
	Images      []ManifestImage `json:"images"`
	// Accepts is the oldest release of each component this platform
	// release supports (the "min" values of its versions.yaml); a
	// component without a minimum is left out.
	Accepts map[string]string `json:"accepts"`
	// Previous lists the earlier stable releases, newest first.
	Previous []releasefeed.Release `json:"previous"`
}

// ManifestImage is one published image of the platform release.
type ManifestImage struct {
	Name   string `json:"name"`
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// ManifestComponent is the newest stable release of one first-party
// component, and the oldest platform release it works with.
type ManifestComponent struct {
	Component   string    `json:"component"`
	Repository  string    `json:"repository"`
	Version     string    `json:"version"`
	PublishedAt time.Time `json:"published_at"`
	NotesURL    string    `json:"notes_url,omitempty"`
	Image       string    `json:"image,omitempty"`
	Digest      string    `json:"digest,omitempty"`
	// RequiresPlatform is the oldest platform release this component
	// release works with ("" = any supported release).
	RequiresPlatform string `json:"requires_platform,omitempty"`
	// Requirements are the compatibility entries behind it, oldest first.
	Requirements []CompatEntry `json:"requirements,omitempty"`
}

// ManifestChart is the newest stable release of the platform Helm chart.
type ManifestChart struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	Version    string `json:"version"`
	AppVersion string `json:"app_version"`
}

// CompatEntry says: releases of Component from From on need platform
// Platform or later, because of Reason. Kept in
// .github/release-feed/compat.json and changed only when a component's
// contract with the platform changes, never per release.
type CompatEntry struct {
	Component string `json:"component"`
	From      string `json:"from"`
	Platform  string `json:"platform"`
	Reason    string `json:"reason"`
}

type compatFile struct {
	Requires []CompatEntry `json:"requires"`
}

var (
	digestRe    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	imageRefRe  = regexp.MustCompile(`^ghcr\.io/openctemio/[a-z0-9-]+:v\d+\.\d+\.\d+$`)
	imageNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	chartVerRe  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

// componentRepos maps each component the feed lists to its repository and
// image: the sensor products of versions.yaml, the SDK and the CI runner.
func componentRepos() map[string][2]string {
	out := map[string][2]string{
		SDKComponent: {SDKRepository, ""},
		CIComponent:  {CIRepository, CIImage},
	}
	for _, p := range versions.Embedded().Products {
		if m := identityRepo.FindStringSubmatch(p.ReleaseIdentity); m != nil {
			out[p.Key] = [2]string{m[1], p.Image}
		}
	}
	return out
}

func readFeedPayload(path string) (releasefeed.Feed, error) {
	var f releasefeed.Feed
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied input
	if err != nil {
		return f, err
	}
	if err := feedsign.DecodeStrict(raw, &f); err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	if err := f.Validate(); err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// newestRelease is the newest release of the feed by version (the feed
// lists stable releases only).
func newestRelease(f releasefeed.Feed) (releasefeed.Release, []releasefeed.Release, error) {
	rs := append([]releasefeed.Release(nil), f.Releases...)
	sort.SliceStable(rs, func(i, j int) bool { return semver.Compare(rs[i].Version, rs[j].Version) > 0 })
	if len(rs) == 0 {
		return releasefeed.Release{}, nil, errors.New("the feed lists no release")
	}
	return rs[0], rs[1:], nil
}

// platformCmd prints the platform release the manifest will describe, so the
// workflow fetches that release's image list and versions.yaml.
func platformCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("platform", flag.ContinueOnError)
	feedPath := fs.String("feed", "", "the feed payload (release-feed build -out)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	f, err := readFeedPayload(*feedPath)
	if err != nil {
		return err
	}
	r, _, err := newestRelease(f)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, r.Version)
	return err
}

type manifestOptions struct {
	feed, images, versionsFile, compat, chartIndex, out string
}

func manifestCmd(args []string, out io.Writer, now time.Time) error {
	var o manifestOptions
	fs := flag.NewFlagSet("manifest", flag.ContinueOnError)
	fs.StringVar(&o.feed, "feed", "", "the feed payload (release-feed build -out)")
	fs.StringVar(&o.images, "images", "", "openctem-images-<tag>.txt of the platform release")
	fs.StringVar(&o.versionsFile, "versions", "", "versions.yaml at the platform release's tag")
	fs.StringVar(&o.compat, "compat", "", "compatibility entries (.github/release-feed/compat.json)")
	fs.StringVar(&o.chartIndex, "chart-index", "", "index.yaml of the Helm repository")
	fs.StringVar(&o.out, "out", ManifestFileName, "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := o.build(now)
	if err != nil {
		return err
	}
	if err := os.WriteFile(o.out, raw, 0o644); err != nil { //nolint:gosec // G306: public manifest
		return err
	}
	_, err = fmt.Fprintf(out, "wrote %s (%d bytes)\n", o.out, len(raw))
	return err
}

func (o *manifestOptions) build(now time.Time) ([]byte, error) {
	if o.feed == "" || o.images == "" || o.versionsFile == "" || o.compat == "" || o.chartIndex == "" {
		return nil, errors.New("-feed, -images, -versions, -compat and -chart-index are required")
	}
	f, err := readFeedPayload(o.feed)
	if err != nil {
		return nil, err
	}
	latest, previous, err := newestRelease(f)
	if err != nil {
		return nil, err
	}
	m := Manifest{Schema: ManifestSchema, GeneratedAt: now.UTC(), Advisories: f.Advisories}
	if m.Advisories == nil {
		m.Advisories = []releasefeed.Advisory{}
	}
	if len(previous) > 10 {
		previous = previous[:10]
	}
	m.Platform = ManifestPlatform{
		Version: latest.Version, PublishedAt: latest.PublishedAt, NotesURL: latest.NotesURL,
		UpgradeURL: UpgradeDocs, Previous: previous,
	}
	if m.Platform.Images, err = readImages(o.images, latest.Version); err != nil {
		return nil, err
	}
	if m.Platform.Accepts, err = readAccepts(o.versionsFile); err != nil {
		return nil, err
	}
	entries, err := readCompat(o.compat)
	if err != nil {
		return nil, err
	}
	repos := componentRepos()
	for _, c := range f.Components {
		rp, ok := repos[c.Component]
		if !ok {
			return nil, fmt.Errorf("component %q is not a known first-party component", c.Component)
		}
		mc := ManifestComponent{
			Component: c.Component, Repository: rp[0], Version: c.Version, PublishedAt: c.PublishedAt,
			NotesURL: c.NotesURL, Image: rp[1], Digest: c.Digest,
		}
		for _, e := range entries {
			if e.Component == c.Component && semver.Compare(c.Version, e.From) >= 0 {
				mc.Requirements = append(mc.Requirements, e)
				if mc.RequiresPlatform == "" || semver.Compare(e.Platform, mc.RequiresPlatform) > 0 {
					mc.RequiresPlatform = e.Platform
				}
			}
		}
		m.Components = append(m.Components, mc)
	}
	if len(m.Components) == 0 {
		return nil, errors.New("the feed lists no component")
	}
	if m.Chart, err = readChart(o.chartIndex); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// readImages reads the signed image list of a platform release:
// "<name> <ref> <digest> <archive> <archive-sha256>" per line, # comments.
func readImages(path, tag string) ([]ManifestImage, error) {
	fh, err := os.Open(path) // #nosec G304 -- operator-supplied input
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var out []ManifestImage
	sc := bufio.NewScanner(fh)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 || !imageNameRe.MatchString(f[0]) || !imageRefRe.MatchString(f[1]) || !digestRe.MatchString(f[2]) {
			return nil, fmt.Errorf("%s:%d: not '<name> <ghcr.io/openctemio/...:vX.Y.Z> <sha256:...>'", path, n)
		}
		if !strings.HasSuffix(f[1], ":"+tag) {
			return nil, fmt.Errorf("%s:%d: %s is not of release %s", path, n, f[1], tag)
		}
		out = append(out, ManifestImage{Name: f[0], Ref: f[1], Digest: f[2]})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no image", path)
	}
	return out, nil
}

func readAccepts(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied input
	if err != nil {
		return nil, err
	}
	vm, err := versions.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := map[string]string{}
	for _, p := range vm.Products {
		if p.Min != "" {
			out[p.Key] = p.Min
		}
	}
	if vm.SDKMin != "" {
		out[SDKComponent] = vm.SDKMin
	}
	if vm.CIRunnerMin != "" {
		out[CIComponent] = vm.CIRunnerMin
	}
	return out, nil
}

func readCompat(path string) ([]CompatEntry, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied input
	if err != nil {
		return nil, err
	}
	var cf compatFile
	if err := feedsign.DecodeStrict(raw, &cf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	repos := componentRepos()
	for i, e := range cf.Requires {
		if _, ok := repos[e.Component]; !ok {
			return nil, fmt.Errorf("%s: entry %d: unknown component %q", path, i, e.Component)
		}
		if !releaseTag.MatchString(e.From) || !releaseTag.MatchString(e.Platform) {
			return nil, fmt.Errorf("%s: entry %d: from and platform must be vX.Y.Z", path, i)
		}
		if strings.TrimSpace(e.Reason) == "" || len(e.Reason) > releasefeed.MaxTitle {
			return nil, fmt.Errorf("%s: entry %d: reason is empty or over %d characters", path, i, releasefeed.MaxTitle)
		}
	}
	sort.SliceStable(cf.Requires, func(i, j int) bool { return semver.Compare(cf.Requires[i].From, cf.Requires[j].From) < 0 })
	return cf.Requires, nil
}

type helmIndex struct {
	Entries map[string][]struct {
		Version    string `yaml:"version"`
		AppVersion string `yaml:"appVersion"`
	} `yaml:"entries"`
}

// readChart picks the newest stable release of the platform chart from the
// Helm repository index.
func readChart(path string) (ManifestChart, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied input
	if err != nil {
		return ManifestChart{}, err
	}
	var idx helmIndex
	if err := yaml.Unmarshal(raw, &idx); err != nil {
		return ManifestChart{}, fmt.Errorf("%s: %w", path, err)
	}
	best := ManifestChart{Name: ChartName, Repository: ChartRepoURL}
	for _, e := range idx.Entries[ChartName] {
		if !chartVerRe.MatchString(e.Version) || !releaseTag.MatchString(e.AppVersion) {
			continue // a pre-release or a malformed entry
		}
		if best.Version == "" || semver.Compare("v"+e.Version, "v"+best.Version) > 0 {
			best.Version, best.AppVersion = e.Version, e.AppVersion
		}
	}
	if best.Version == "" {
		return ManifestChart{}, fmt.Errorf("%s: no stable %s chart", path, ChartName)
	}
	return best, nil
}
