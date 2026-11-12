// Command release-feed builds the release feed an instance's version check
// reads (docs/rfcs/RFC-105-version-check-and-usage-telemetry.md). The feed is
// signed keyless by the release-feed workflow (cosign sign-blob with its GitHub
// OIDC identity); an instance verifies the Sigstore bundle offline
// (releasefeed.SignerIdentityPattern).
//
// Usage (from server/), as the workflow runs it:
//
//	gh release list --json tagName,publishedAt,isDraft,isPrerelease --limit 200 > releases.json
//	go run ./cmd/release-feed components                  # "<component> <repository> <image or ->" per line
//	../.github/scripts/release/feed-components.sh > components.json
//	go run ./cmd/release-feed build -releases releases.json -advisories advisories.json \
//	    -components components.json -out feed.json         # the exact bytes to sign
//	cosign sign-blob --yes --bundle feed.sigstore.json feed.json
//	go run ./cmd/release-feed assemble -feed feed.json -bundle feed.sigstore.json -out openctem-releases.json
//	go run ./cmd/release-feed verify [-trusted-root trusted_root.json] openctem-releases.json
//
// The components are the first-party sensor products of versions.yaml, the
// SDK and the CI runner: the feed carries the newest stable release of each,
// so an instance learns a sensor, SDK or CI runner release without an
// OpenCTEM release
// (docs/rfcs/RFC-037-versioning-and-release-train.md §12).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/openctemio/openctem/server/internal/versions"
	cpsigstore "github.com/openctemio/openctem/server/pkg/contentpkg/sigstore"
	"github.com/openctemio/openctem/server/pkg/feedsign"
	"github.com/openctemio/openctem/server/pkg/releasefeed"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, time.Now().UTC()); err != nil {
		fmt.Fprintln(os.Stderr, "release-feed:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer, now time.Time) error {
	if len(args) == 0 {
		return errors.New("usage: release-feed components|build|assemble|verify [flags]")
	}
	switch args[0] {
	case "components":
		return components(out)
	case "build":
		return build(args[1:], out, now)
	case "assemble":
		return assemble(args[1:], out)
	case "verify":
		return verify(args[1:], out, now)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// ghRelease is one row of `gh release list --json tagName,publishedAt,isDraft,isPrerelease`.
type ghRelease struct {
	TagName      string    `json:"tagName"`
	PublishedAt  time.Time `json:"publishedAt"`
	IsDraft      bool      `json:"isDraft"`
	IsPrerelease bool      `json:"isPrerelease"`
}

// advisoriesFile is the committed advisories list.
type advisoriesFile struct {
	Advisories []releasefeed.Advisory `json:"advisories"`
}

var (
	releaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)
	repoName   = regexp.MustCompile(`^openctemio/[A-Za-z0-9._-]+$`)
)

// SDKComponent is the SDK's component name (its versions.yaml section) and
// SDKRepository its repository. CIComponent is the CI runner's, with its
// repository and image: a CI runner release counts once its image is
// published, since the console's snippets for most CI systems run it.
const (
	SDKComponent  = "sdk"
	SDKRepository = "openctemio/sdk-go"
	CIComponent   = versions.CIKey
	CIRepository  = "openctemio/ci"
	CIImage       = "ghcr.io/openctemio/ci"
)

// identityRepo extracts the repository from a release identity
// (https://github.com/openctemio/<repo>/.github/workflows/<file>).
var identityRepo = regexp.MustCompile(`^https://github\.com/(openctemio/[A-Za-z0-9._-]+)/\.github/workflows/`)

// components prints the first-party components the feed lists, one per line:
// the component name, its repository and its image repository ("-" for
// none): the sensor products, the SDK and the CI runner. The publishing script resolves each one's newest release.
func components(out io.Writer) error {
	for _, p := range versions.Embedded().Products {
		m := identityRepo.FindStringSubmatch(p.ReleaseIdentity)
		if m == nil {
			return fmt.Errorf("product %s: no repository in its release identity", p.Key)
		}
		if _, err := fmt.Fprintf(out, "%s %s %s\n", p.Key, m[1], p.Image); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(out, "%s %s -\n", SDKComponent, SDKRepository); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "%s %s %s\n", CIComponent, CIRepository, CIImage)
	return err
}

type buildOptions struct {
	releases, advisories, components, repo, out string
	days                                        int
}

func build(args []string, out io.Writer, now time.Time) error {
	var o buildOptions
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.StringVar(&o.releases, "releases", "", "JSON from `gh release list --json tagName,publishedAt,isDraft,isPrerelease`")
	fs.StringVar(&o.advisories, "advisories", "", "advisories file ({\"advisories\": [...]}); optional")
	fs.StringVar(&o.components, "components", "", "components file (a JSON array from feed-components.sh); optional")
	fs.StringVar(&o.repo, "repo", "openctemio/openctem", "repository whose release pages the notes links name")
	fs.IntVar(&o.days, "days", 30, "feed validity in days (1 to 45)")
	fs.StringVar(&o.out, "out", "feed.json", "output file: the feed payload to sign")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := o.run(now)
	if err != nil {
		return err
	}
	if err := os.WriteFile(o.out, raw, 0o644); err != nil { //nolint:gosec // G306: public feed payload
		return err
	}
	_, err = fmt.Fprintf(out, "wrote %s (%d bytes)\n", o.out, len(raw))
	return err
}

func (o *buildOptions) run(now time.Time) ([]byte, error) {
	if o.days < 1 || time.Duration(o.days)*24*time.Hour > releasefeed.MaxFeedValidity {
		return nil, errors.New("-days must be 1 to 45")
	}
	if !repoName.MatchString(o.repo) {
		return nil, fmt.Errorf("-repo %q", o.repo)
	}
	var err error
	feed := releasefeed.Feed{Sequence: uint64(now.Unix()), IssuedAt: now, ExpiresAt: now.Add(time.Duration(o.days) * 24 * time.Hour)} //nolint:gosec // now is after 1970
	if feed.Releases, err = readReleases(o.releases, o.repo); err != nil {
		return nil, err
	}
	if o.advisories != "" {
		raw, err := os.ReadFile(o.advisories)
		if err != nil {
			return nil, err
		}
		var af advisoriesFile
		if err := feedsign.DecodeStrict(raw, &af); err != nil {
			return nil, fmt.Errorf("%s: %w", o.advisories, err)
		}
		feed.Advisories = af.Advisories
	}
	if feed.Advisories == nil {
		feed.Advisories = []releasefeed.Advisory{}
	}
	if o.components != "" {
		raw, err := os.ReadFile(o.components)
		if err != nil {
			return nil, err
		}
		if err := feedsign.DecodeStrict(raw, &feed.Components); err != nil {
			return nil, fmt.Errorf("%s: %w", o.components, err)
		}
	}
	return releasefeed.Payload(feed)
}

func readReleases(path, repo string) ([]releasefeed.Release, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied input
	if err != nil {
		return nil, err
	}
	var rows []ghRelease
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := make([]releasefeed.Release, 0, len(rows))
	for _, r := range rows {
		if r.IsDraft || r.IsPrerelease || !releaseTag.MatchString(r.TagName) || r.PublishedAt.IsZero() {
			continue
		}
		out = append(out, releasefeed.Release{Version: r.TagName, PublishedAt: r.PublishedAt.UTC(),
			NotesURL: "https://github.com/" + repo + "/releases/tag/" + r.TagName})
		if len(out) == releasefeed.MaxReleases {
			break
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no published release in the list")
	}
	return out, nil
}

func assemble(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("assemble", flag.ContinueOnError)
	feedPath := fs.String("feed", "", "the feed payload that was signed")
	bundlePath := fs.String("bundle", "", "the Sigstore bundle cosign sign-blob wrote")
	dest := fs.String("out", releasefeed.FileName, "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *feedPath == "" || *bundlePath == "" {
		return errors.New("-feed and -bundle are required")
	}
	payload, err := os.ReadFile(*feedPath) // #nosec G304 -- operator-supplied input
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(*bundlePath) // #nosec G304 -- operator-supplied input
	if err != nil {
		return err
	}
	raw, err := releasefeed.Assemble(payload, sig)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*dest, raw, 0o644); err != nil { //nolint:gosec // G306: public, signed feed
		return err
	}
	_, err = fmt.Fprintf(out, "wrote %s (%d bytes)\n", *dest, len(raw))
	return err
}

func verify(args []string, out io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	root := fs.String("trusted-root", "", "Sigstore trusted root file; default: the one embedded in this build")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: verify [-trusted-root <file>] <file>")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	sv, err := cpsigstore.New(*root)
	if err != nil {
		return err
	}
	v, err := releasefeed.Verify(raw, releasefeed.Trust{Verifier: sv}, now)
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintf(out, "ok: sequence %d, signed %s, %d releases, %d advisories, %d components, expires %s\n",
		v.Feed.Sequence, v.SignedAt.Format(time.RFC3339), len(v.Feed.Releases), len(v.Feed.Advisories), len(v.Feed.Components),
		v.Feed.ExpiresAt.Format(time.RFC3339)); err != nil {
		return err
	}
	for _, c := range v.Feed.Components {
		if _, err := fmt.Fprintf(out, "  %s %s %s\n", c.Component, c.Version, c.Digest); err != nil {
			return err
		}
	}
	return nil
}
