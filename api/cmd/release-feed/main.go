// Command release-feed creates the release feed keys, signs its key set and
// builds the signed release feed an instance's version check reads
// (docs/rfcs/RFC-105-version-check-and-usage-telemetry.md). The root runs on
// an offline machine; the online key in the release pipeline; an instance
// only verifies.
//
// Usage (from api/):
//
//	go run ./cmd/release-feed keygen -out root.key        # prints the key id and public key, never the seed
//	go run ./cmd/release-feed keyset -root root.key -online <public key hex>[,<hex>] -version 1 -days 180 -out keyset.dsse.json
//	gh release list --json tagName,publishedAt,isDraft,isPrerelease --limit 200 > releases.json
//	go run ./cmd/release-feed build -keyset keyset.dsse.json -key-env RELEASE_FEED_SIGNING_KEY \
//	    -releases releases.json -advisories advisories.json -out openctem-releases.json
//	go run ./cmd/release-feed verify -root SHA256:<hex> openctem-releases.json
//
// A key file holds the 32-byte Ed25519 seed in hex (mode 0600).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/feedsign"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/releasefeed"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, time.Now().UTC()); err != nil {
		fmt.Fprintln(os.Stderr, "release-feed:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer, now time.Time) error {
	if len(args) == 0 {
		return errors.New("usage: release-feed keygen|keyset|build|verify [flags]")
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:], out)
	case "keyset":
		return keyset(args[1:], now)
	case "build":
		return build(args[1:], out, now)
	case "verify":
		return verify(args[1:], out, now)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func keygen(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	path := fs.String("out", "", "private key file to create (refuses to overwrite)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("-out is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(hex.EncodeToString(priv.Seed()) + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "key id:     %s\npublic key: %s\n", jobsign.KeyID(pub), hex.EncodeToString(pub))
	return err
}

func parseSeed(s, what string) (ed25519.PrivateKey, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: not a hex Ed25519 seed", what)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func readKeyFile(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied key file
	if err != nil {
		return nil, err
	}
	return parseSeed(string(raw), path)
}

func keyset(args []string, now time.Time) error {
	fs := flag.NewFlagSet("keyset", flag.ContinueOnError)
	rootPath := fs.String("root", "", "root private key file")
	online := fs.String("online", "", "online public keys, hex, comma separated")
	version := fs.Uint64("version", 0, "key set version (higher than every earlier one)")
	days := fs.Int("days", 180, "validity in days (at most 180)")
	path := fs.String("out", "keyset.dsse.json", "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root, err := readKeyFile(*rootPath)
	if err != nil {
		return err
	}
	var pubs []ed25519.PublicKey
	for _, h := range strings.Split(*online, ",") {
		b, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil || len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("online key %q is not a hex Ed25519 public key", h)
		}
		pubs = append(pubs, b)
	}
	validity := time.Duration(*days) * 24 * time.Hour
	if *version == 0 || *days < 1 || validity > feedsign.MaxKeySetValidity {
		return errors.New("-version must be set and -days must be 1 to 180")
	}
	env, err := releasefeed.SignKeySet(root, *version, now, now.Add(validity), pubs...)
	if err != nil {
		return err
	}
	return os.WriteFile(*path, env, 0o644) // #nosec G306 -- public, signed metadata
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

type buildOptions struct {
	keySet, keyFile, keyEnv, releases, advisories, repo, out string
	days                                                     int
}

func build(args []string, out io.Writer, now time.Time) error {
	var o buildOptions
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.StringVar(&o.keySet, "keyset", "", "signed key set file")
	fs.StringVar(&o.keyFile, "key", "", "online private key file")
	fs.StringVar(&o.keyEnv, "key-env", "", "environment variable holding the online key seed (hex), instead of -key")
	fs.StringVar(&o.releases, "releases", "", "JSON from `gh release list --json tagName,publishedAt,isDraft,isPrerelease`")
	fs.StringVar(&o.advisories, "advisories", "", "advisories file ({\"advisories\": [...]}); optional")
	fs.StringVar(&o.repo, "repo", "openctemio/openctem", "repository whose release pages the notes links name")
	fs.IntVar(&o.days, "days", 30, "feed validity in days (1 to 45)")
	fs.StringVar(&o.out, "out", releasefeed.FileName, "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := o.run(now)
	if err != nil {
		return err
	}
	if err := os.WriteFile(o.out, raw, 0o644); err != nil { // #nosec G306 -- public, signed feed
		return err
	}
	_, err = fmt.Fprintf(out, "wrote %s (%d bytes)\n", o.out, len(raw))
	return err
}

func (o *buildOptions) onlineKey() (ed25519.PrivateKey, error) {
	switch {
	case o.keyEnv != "" && o.keyFile != "":
		return nil, errors.New("give -key or -key-env, not both")
	case o.keyEnv != "":
		v := os.Getenv(o.keyEnv)
		if v == "" {
			return nil, fmt.Errorf("%s is empty", o.keyEnv)
		}
		return parseSeed(v, o.keyEnv)
	case o.keyFile != "":
		return readKeyFile(o.keyFile)
	}
	return nil, errors.New("-key or -key-env is required")
}

func (o *buildOptions) run(now time.Time) ([]byte, error) {
	if o.days < 1 || time.Duration(o.days)*24*time.Hour > releasefeed.MaxFeedValidity {
		return nil, errors.New("-days must be 1 to 45")
	}
	if !repoName.MatchString(o.repo) {
		return nil, fmt.Errorf("-repo %q", o.repo)
	}
	ks, err := os.ReadFile(o.keySet)
	if err != nil {
		return nil, err
	}
	key, err := o.onlineKey()
	if err != nil {
		return nil, err
	}
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
	return releasefeed.Build(ks, key, feed)
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

func verify(args []string, out io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	root := fs.String("root", "", "pinned root key id (SHA256:<hex>); default: the roots pinned in this build")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: verify [-root SHA256:<hex>] <file>")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	roots := releasefeed.PinnedRoots
	if *root != "" {
		roots = []string{*root}
	}
	v, err := releasefeed.Verify(raw, releasefeed.Trust{Roots: roots}, now)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "ok: sequence %d, key set version %d, %d releases, %d advisories, expires %s\n",
		v.Feed.Sequence, v.KeySetVersion, len(v.Feed.Releases), len(v.Feed.Advisories), v.Feed.ExpiresAt.Format(time.RFC3339))
	return err
}
