package vulnfeed

// Probe: the console's "Test fetch" of a release URL or a mirror. It
// fetches the key set and the newest pointer from one origin with the same
// SSRF-guarded feed client and size caps as an import, verifies the key set
// against the pinned root (and the key set version already accepted) and
// the pointer against that key set, and reports the outcome. It never
// fetches a manifest or a chunk and never writes the corpus, the checkpoint
// or the status row.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/contract/transfer/bundle"

	"github.com/openctemio/openctem/server/internal/app/feedstatus"
	"github.com/openctemio/openctem/server/pkg/httpsec"
	"github.com/openctemio/openctem/server/pkg/vulnbundle"
)

// Probe outcome codes (ProbeResult.Error).
const (
	ProbeBlockedAddress = "blocked_address"
	ProbeUnreachable    = "unreachable"
	ProbeNotFound       = "not_found"
	ProbeHTTPError      = "http_error"
	ProbeRootMismatch   = "root_mismatch"
	ProbePointerInvalid = "pointer_invalid"
	ProbeNotConfigured  = "not_configured"
)

// probeTimeout bounds the test of one origin.
const probeTimeout = 20 * time.Second

// ProbeResult is the outcome of testing one origin.
type ProbeResult struct {
	// Origin is the URL tested (the release base URL or a mirror).
	Origin string `json:"origin"`
	OK     bool   `json:"ok"`
	// Format is the bundle format found: v2 (chunked) or v1.
	Format string `json:"format,omitempty"`
	// Sequence and CreatedAt describe the newest release the origin
	// serves; KeySetVersion the key set that signed it.
	Sequence      uint64    `json:"sequence,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitzero"`
	KeySetVersion uint64    `json:"keyset_version,omitempty"`
	// Behind: the origin's newest release is older than the one applied.
	Behind bool `json:"behind,omitempty"`
	// Error is a probe outcome code when OK is false; HTTPStatus the
	// status of an http_error.
	Error      string `json:"error,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

// Probe tests base (a release base URL: files under /latest/download) and
// each mirror (files at the mirror itself). The caller validated every URL.
func (im *Importer) Probe(ctx context.Context, base string, mirrors []string) []ProbeResult {
	out := make([]ProbeResult, 0, 1+len(mirrors))
	floor, applied := im.probeFloor(ctx)
	if base != "" {
		out = append(out, im.probeOne(ctx, base, strings.TrimRight(base, "/")+"/latest/download", true, floor, applied))
	}
	for _, m := range mirrors {
		out = append(out, im.probeOne(ctx, m, strings.TrimRight(m, "/"), false, floor, applied))
	}
	return out
}

// probeFloor is the key set version already accepted and the sequence
// applied (zero when unreadable: the test is then only less strict).
func (im *Importer) probeFloor(ctx context.Context) (uint64, uint64) {
	if im.status == nil {
		return 0, 0
	}
	st, err := im.status.GetBySource(ctx, SourceName)
	if err != nil || st == nil {
		return 0, 0
	}
	cur := readState(st.Metadata())
	if im.chunks != nil {
		if cp, err := im.chunks.FeedCheckpoint().Load(ctx); err == nil {
			cur.Applied = max(cur.Applied, cp.Applied)
		}
	}
	return cur.KeySetVersion, cur.Applied
}

func (im *Importer) probeOne(ctx context.Context, origin, dirURL string, v1Fallback bool, floor, applied uint64) ProbeResult {
	res := ProbeResult{Origin: origin}
	if im.cfg.RootKeyID == "" {
		res.Error = ProbeNotConfigured
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	dir, err := os.MkdirTemp(im.tmp, "vulnfeed-probe-*")
	if err != nil {
		res.Error = ProbeUnreachable
		return res
	}
	defer func() { _ = os.RemoveAll(dir) }()
	now := im.now()

	if err := im.download(ctx, dirURL+"/"+bundle.KeySetFile, filepath.Join(dir, bundle.KeySetFile), vulnbundle.MaxKeySetBytes); err != nil {
		return probeFetchError(res, err)
	}
	raw, err := readCapped(dir, bundle.KeySetFile, vulnbundle.MaxKeySetBytes)
	if err != nil {
		res.Error = ProbeRootMismatch
		return res
	}
	ks, err := vulnbundle.VerifyKeySet(raw, im.cfg.RootKeyID, floor, now)
	if err != nil {
		res.Error = ProbeRootMismatch
		return res
	}
	res.KeySetVersion = ks.Version

	err = im.download(ctx, dirURL+"/"+bundle.PointerFile, filepath.Join(dir, bundle.PointerFile), 64<<10)
	var he *feedstatus.HTTPError
	if err != nil && v1Fallback && errors.As(err, &he) && he.Status == http.StatusNotFound {
		// The release serves no chunked pointer: the v1 reader is used.
		if err := im.download(ctx, dirURL+"/"+vulnbundle.LatestFile, filepath.Join(dir, vulnbundle.LatestFile), vulnbundle.MaxManifestBytes); err != nil {
			return probeFetchError(res, err)
		}
		v, err := vulnbundle.VerifyPointer(dir, vulnbundle.Options{PinnedRoot: im.cfg.RootKeyID, MinKeySetVer: floor, Now: now})
		if err != nil {
			res.Error = ProbePointerInvalid
			return res
		}
		res.OK, res.Format, res.Sequence, res.CreatedAt = true, "v1", v.Latest.Sequence, v.Latest.CreatedAt
		res.Behind = applied > 0 && v.Latest.Sequence < applied
		return res
	}
	if err != nil {
		return probeFetchError(res, err)
	}
	pubs := make([]ed25519.PublicKey, 0, len(ks.Keys))
	for _, k := range ks.Keys {
		pub, err := k.Decode()
		if err != nil {
			res.Error = ProbeRootMismatch
			return res
		}
		pubs = append(pubs, pub)
	}
	var p bundle.Pointer
	if err := verifiedJSON(im.logger, bundle.NewEd25519Verifier(pubs...), dir, bundle.PointerFile, nil,
		bundle.PointerPayloadType(FeedV2), 64<<10, &p); err != nil {
		res.Error = ProbePointerInvalid
		return res
	}
	if err := p.Validate(FeedV2, now, v2Limits); err != nil {
		res.Error = ProbePointerInvalid
		return res
	}
	res.OK, res.Format, res.Sequence, res.CreatedAt = true, "v2", p.Sequence, p.CreatedAt
	res.Behind = applied > 0 && p.Sequence < applied
	return res
}

// probeFetchError classifies a failed download without echoing what the
// origin sent.
func probeFetchError(res ProbeResult, err error) ProbeResult {
	var he *feedstatus.HTTPError
	switch {
	case errors.Is(err, httpsec.ErrBlockedDestination):
		res.Error = ProbeBlockedAddress
	case errors.As(err, &he) && he.Status == http.StatusNotFound:
		res.Error = ProbeNotFound
	case errors.As(err, &he):
		res.Error, res.HTTPStatus = ProbeHTTPError, he.Status
	default:
		res.Error = ProbeUnreachable
	}
	return res
}
