// Command content-bundle creates the catalog keys and builds the signed
// first-party content bundle (api/docs/rfcs/RFC-099-content-packages.md).
// It runs where the catalog keys are (an offline machine for the root, the
// release pipeline for the online key); an instance only verifies.
//
// Usage (from api/):
//
//	go run ./cmd/content-bundle keygen -out root.key
//	go run ./cmd/content-bundle keyset -root root.key -online <public key hex>[,<hex>] -version 1 -days 365 -out keyset.dsse.json
//	go run ./cmd/content-bundle build -keyset keyset.dsse.json -online-key online.key -sequence 7 \
//	    -sast-rules dist/ -image sensor=sha256:<hex>:<size>:GPL-3.0-only \
//	    -feed program-feed=feeds/program/keyset.dsse.json -out openctem-content.tar
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
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/versions"
	"github.com/openctemio/openctem/api/pkg/contentpkg"
	"github.com/openctemio/openctem/api/pkg/contentpkg/firstparty"
	"github.com/openctemio/openctem/api/pkg/feedsign"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: content-bundle keygen|keyset|build [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "keyset":
		err = keyset(os.Args[2:])
	case "build":
		err = build(os.Args[2:], time.Now().UTC())
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "content-bundle:", err)
		os.Exit(1)
	}
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "private key file to create (refuses to overwrite)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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
	fmt.Printf("key id:     %s\npublic key: %s\n", contentpkg.RootKeyID(pub), hex.EncodeToString(pub))
	return nil
}

func readKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied key file
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: not a hex Ed25519 seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func keyset(args []string) error {
	fs := flag.NewFlagSet("keyset", flag.ContinueOnError)
	rootPath := fs.String("root", "", "root private key file")
	online := fs.String("online", "", "online public keys, hex, comma separated")
	version := fs.Uint64("version", 0, "key set version (higher than every earlier one)")
	days := fs.Int("days", 365, "validity in days (at most 365)")
	out := fs.String("out", "keyset.dsse.json", "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root, err := readKey(*rootPath)
	if err != nil {
		return err
	}
	parts := strings.Split(*online, ",")
	pubs := make([]ed25519.PublicKey, 0, len(parts))
	for _, h := range parts {
		b, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil || len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("online key %q is not a hex Ed25519 public key", h)
		}
		pubs = append(pubs, b)
	}
	if *version == 0 || *days < 1 || time.Duration(*days)*24*time.Hour > contentpkg.MaxKeySetValidity {
		return errors.New("-version must be set and -days must be 1 to 365")
	}
	now := time.Now().UTC()
	env, err := contentpkg.SignKeySet(root, *version, now, now.Add(time.Duration(*days)*24*time.Hour), pubs...)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, env, 0o644) // #nosec G306 -- public, signed metadata
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// buildOptions are the inputs of a first-party bundle.
type buildOptions struct {
	keySet, onlineKey, sastDir, revocations, out, platform string
	sequence                                               uint64
	days                                                   int
	images, feeds                                          multi
}

func build(args []string, now time.Time) error {
	var o buildOptions
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.StringVar(&o.keySet, "keyset", "", "signed key set file")
	fs.StringVar(&o.onlineKey, "online-key", "", "online private key file")
	fs.Uint64Var(&o.sequence, "sequence", uint64(now.Unix()), "index sequence (default: now, in seconds)") //nolint:gosec // positive
	fs.IntVar(&o.days, "days", 30, "index validity in days (at most 90); the revocation list is valid min(days, 30)")
	fs.StringVar(&o.sastDir, "sast-rules", "", "directory with sast-rules-<v>.tar.gz and its .sigstore.json")
	fs.Var(&o.images, "image", "product=sha256:<hex>:<size>:<SPDX> for each sensor product in versions.yaml (repeatable)")
	fs.Var(&o.feeds, "feed", "name=path of a feed key set (program-feed, vulnerability-feed; repeatable)")
	fs.StringVar(&o.revocations, "revocations", "", "JSON file: {\"sequence\": N, \"entries\": [...]} (default: an empty list at the index sequence)")
	fs.StringVar(&o.platform, "platform", ">="+strings.TrimPrefix(versions.PlatformRelease(), "v"), "platform range of every package")
	fs.StringVar(&o.out, "out", "openctem-content.tar", "output bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return o.run(now)
}

func (o *buildOptions) run(now time.Time) error {
	ks, err := os.ReadFile(o.keySet)
	if err != nil {
		return err
	}
	online, err := readKey(o.onlineKey)
	if err != nil {
		return err
	}
	if o.days < 1 || o.days > 90 {
		return errors.New("-days must be 1 to 90")
	}
	pkgs, err := o.packages(now)
	if err != nil {
		return err
	}
	rv, err := o.revocationList(now)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(o.out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) // #nosec G302 G304 -- public, signed bundle
	if err != nil {
		return err
	}
	in := contentpkg.BundleInput{KeySet: ks, Online: online, Sequence: o.sequence, IssuedAt: now,
		ExpiresAt: now.Add(time.Duration(o.days) * 24 * time.Hour), Revocations: rv, Packages: pkgs}
	if err := contentpkg.WriteBundle(f, in); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("wrote %s: %d packages, index sequence %d\n", o.out, len(pkgs), o.sequence)
	return nil
}

func (o *buildOptions) packages(now time.Time) ([]contentpkg.PackageInput, error) {
	pkgs := make([]contentpkg.PackageInput, 0, 1+len(o.images)+len(o.feeds))
	if o.sastDir != "" {
		p, err := sastPackage(o.sastDir, o.platform, now)
		if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
	imgs := map[string]firstparty.Image{}
	for _, s := range o.images {
		key, img, err := parseImage(s)
		if err != nil {
			return nil, err
		}
		imgs[key] = img
	}
	keys := make([]string, 0, len(imgs))
	for k := range imgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		var prod *versions.Product
		for _, p := range versions.Products() {
			if p.Key == k {
				prod = &p
			}
		}
		if prod == nil {
			return nil, fmt.Errorf("-image %s: no such product in versions.yaml", k)
		}
		m, err := firstparty.SensorProduct(*prod, imgs[k], o.platform)
		if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, contentpkg.PackageInput{ManifestRaw: m, Origin: contentpkg.OriginFirstParty, ReviewedAt: now})
	}
	for _, s := range o.feeds {
		p, err := feedPackage(s, o.platform, now)
		if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		return nil, errors.New("nothing to put in the bundle")
	}
	return pkgs, nil
}

func sastPackage(dir, platform string, now time.Time) (contentpkg.PackageInput, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "sast-rules-*.tar.gz"))
	if err != nil || len(matches) != 1 {
		return contentpkg.PackageInput{}, fmt.Errorf("-sast-rules: want exactly one sast-rules-<version>.tar.gz in %s", dir)
	}
	art, err := os.ReadFile(matches[0])
	if err != nil {
		return contentpkg.PackageInput{}, err
	}
	sig, err := os.ReadFile(matches[0] + ".sigstore.json")
	if err != nil {
		return contentpkg.PackageInput{}, fmt.Errorf("-sast-rules: the release signature: %w", err)
	}
	version := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(matches[0]), "sast-rules-"), ".tar.gz")
	m, err := firstparty.SASTRules(version, art, "", platform)
	if err != nil {
		return contentpkg.PackageInput{}, err
	}
	return contentpkg.PackageInput{ManifestRaw: m, Artifact: art, Publisher: sig, Origin: contentpkg.OriginFirstParty, ReviewedAt: now}, nil
}

func parseImage(s string) (string, firstparty.Image, error) {
	key, rest, ok := strings.Cut(s, "=")
	parts := strings.SplitN(rest, ":", 4)
	if !ok || len(parts) != 4 || parts[0] != "sha256" {
		return "", firstparty.Image{}, fmt.Errorf("-image %q: want product=sha256:<hex>:<size>:<SPDX>", s)
	}
	size, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", firstparty.Image{}, fmt.Errorf("-image %q: size", s)
	}
	return key, firstparty.Image{Digest: "sha256:" + parts[1], Size: size, SPDX: parts[3]}, nil
}

var feedTitles = map[string]string{ //nolint:gochecknoglobals // read-only
	"program-feed":       "Public bug bounty program feed",
	"vulnerability-feed": "Vulnerability feed",
}

func feedPackage(s, platform string, now time.Time) (contentpkg.PackageInput, error) {
	name, path, ok := strings.Cut(s, "=")
	title, known := feedTitles[name]
	if !ok || !known {
		return contentpkg.PackageInput{}, fmt.Errorf("-feed %q: want program-feed=<path> or vulnerability-feed=<path>", s)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied file
	if err != nil {
		return contentpkg.PackageInput{}, err
	}
	// The payload type differs per feed; only the version is read here
	// (the instance checks the feed key set with the feed's pinned root).
	var env struct {
		Payload []byte `json:"payload"`
	}
	var ks struct {
		Version uint64 `json:"version"`
	}
	if len(raw) > feedsign.MaxKeySetBytes || json.Unmarshal(raw, &env) != nil || json.Unmarshal(env.Payload, &ks) != nil || ks.Version == 0 {
		return contentpkg.PackageInput{}, fmt.Errorf("-feed %s: not a signed key set", name)
	}
	m, err := firstparty.Feed(name, title, ks.Version, raw, platform)
	if err != nil {
		return contentpkg.PackageInput{}, err
	}
	return contentpkg.PackageInput{ManifestRaw: m, Origin: contentpkg.OriginFirstParty, ReviewedAt: now}, nil
}

func (o *buildOptions) revocationList(now time.Time) (contentpkg.Revocations, error) {
	validity := time.Duration(min(o.days, 30)) * 24 * time.Hour
	rv := contentpkg.Revocations{Sequence: o.sequence, IssuedAt: now, ExpiresAt: now.Add(validity)}
	if o.revocations == "" {
		return rv, nil
	}
	raw, err := os.ReadFile(o.revocations)
	if err != nil {
		return rv, err
	}
	var in struct {
		Sequence uint64                       `json:"sequence"`
		Entries  []contentpkg.RevocationEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return rv, fmt.Errorf("-revocations: %w", err)
	}
	if in.Sequence == 0 {
		return rv, errors.New("-revocations: sequence is required")
	}
	rv.Sequence, rv.Entries = in.Sequence, in.Entries
	return rv, nil
}
