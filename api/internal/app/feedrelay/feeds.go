package feedrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/vulnfeed"
	dom "github.com/openctemio/openctem/api/pkg/domain/feedrelay"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Origins returns the canonical spelling of each origin, dropping the ones
// that are not https origins (configuration already validates them).
func Origins(urls ...string) []string {
	out := make([]string, 0, len(urls))
	seen := map[string]bool{}
	for _, u := range urls {
		if o := jobsign.NormalizeFeedOrigin(u); o != "" && !seen[o] && len(out) < jobsign.MaxFeedOrigins {
			seen[o] = true
			out = append(out, o)
		}
	}
	return out
}

// VulnFeed relays the vulnerability feed (and its KEV, EPSS, alias and id
// side files) for the importer, which reads the spool in relay mode.
type VulnFeed struct {
	Importer *vulnfeed.Importer
	// URLs are the release origin (VULNFEED_BASE_URL + /latest/download) and
	// the mirrors.
	URLs []string
}

// Name implements Feed.
func (v *VulnFeed) Name() string { return dom.FeedVulnFeed }

// Origins implements Feed.
func (v *VulnFeed) Origins() []string { return Origins(v.URLs...) }

// Interval implements Feed: the collector publishes hourly; the importer
// runs every 20 minutes.
func (v *VulnFeed) Interval() time.Duration { return 20 * time.Minute }

// Head implements Feed.
func (v *VulnFeed) Head() Plan { return fromVulnPlan(vulnfeed.RelayHead()) }

// Plan implements Feed.
func (v *VulnFeed) Plan(ctx context.Context, dir string) (Plan, error) {
	p, err := v.Importer.RelayPlan(ctx, dir)
	if err != nil {
		return Plan{}, err
	}
	return fromVulnPlan(p), nil
}

// Import implements Feed: the importer verifies and applies the spool, then
// files the current release no longer names are removed.
func (v *VulnFeed) Import(ctx context.Context, dir string) error {
	if _, err := v.Importer.Run(ctx); err != nil {
		return err
	}
	prune(dir, v.Importer.RelayKeep(dir))
	return nil
}

func fromVulnPlan(p vulnfeed.RelayPlan) Plan {
	out := Plan{Phase: p.Phase, Ready: p.Ready}
	for _, f := range p.Files {
		out.Files = append(out.Files, dom.File{Name: f.Name, SHA256: f.SHA256, Size: f.Size, MaxBytes: f.MaxBytes})
	}
	return out
}

// prune removes the spool's regular files that keep does not name.
func prune(dir string, keep map[string]bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Type().IsRegular() && !keep[e.Name()] && !strings.HasPrefix(e.Name(), ".") {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// ReleaseImporter applies a release feed file (versioncheck.Service).
type ReleaseImporter interface {
	ImportRelayed(ctx context.Context, raw []byte) error
}

// maxReleaseFeedBytes caps the release feed file.
const maxReleaseFeedBytes = 1 << 20

// VersionCheck relays the signed release feed of the version check: one
// file, verified with the version check's pinned keys on import.
type VersionCheck struct {
	Service ReleaseImporter
	// URL is VERSION_CHECK_URL (the file's full URL).
	URL string
}

func (v *VersionCheck) split() (origin, name string) {
	u, err := url.Parse(v.URL)
	if err != nil {
		return "", ""
	}
	name = path.Base(u.Path)
	u.Path = path.Dir(u.Path)
	return jobsign.NormalizeFeedOrigin(u.String()), name
}

// Name implements Feed.
func (v *VersionCheck) Name() string { return dom.FeedVersionCheck }

// Origins implements Feed.
func (v *VersionCheck) Origins() []string {
	o, _ := v.split()
	return Origins(o)
}

// Interval implements Feed.
func (v *VersionCheck) Interval() time.Duration { return 24 * time.Hour }

// Head implements Feed.
func (v *VersionCheck) Head() Plan {
	_, name := v.split()
	if !nameRe.MatchString(name) {
		return Plan{}
	}
	return Plan{Phase: dom.PhaseHead, Files: []dom.File{{Name: name, MaxBytes: maxReleaseFeedBytes}}}
}

// Plan implements Feed: the one file is either there or the cycle failed.
func (v *VersionCheck) Plan(_ context.Context, dir string) (Plan, error) {
	_, name := v.split()
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		return Plan{}, err
	}
	return Plan{Ready: true}, nil
}

// Import implements Feed.
func (v *VersionCheck) Import(ctx context.Context, dir string) error {
	_, name := v.split()
	f, err := os.Open(filepath.Join(dir, filepath.Base(name)))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxReleaseFeedBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxReleaseFeedBytes {
		return errors.New("release feed file over its cap")
	}
	if err := v.Service.ImportRelayed(ctx, raw); err != nil {
		return fmt.Errorf("release feed: %w", err)
	}
	return nil
}
