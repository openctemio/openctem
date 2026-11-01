package vulnfeed

// Relay delivery (docs/rfcs/RFC-142-feed-relay.md). On a platform with no
// outbound access a platform sensor relays the release files into a local
// spool directory, and the importer reads that directory as its only origin
// (as a bundle directory). RelayPlan tells the relay what to fetch next. It
// verifies what the spool already holds with the same pinned root and key
// set floor as the import, so a file a relay altered is asked for again,
// never trusted; the import verifies everything once more before applying.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/openctemio/ctis/transfer/bundle"

	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

// RelayFile is one file the relay is asked for. SHA256 and Size pin it when
// a verified manifest names it.
type RelayFile struct {
	Name     string
	SHA256   string
	Size     int64
	MaxBytes int64
}

// RelayPlan is what the relay should fetch next.
type RelayPlan struct {
	// Files to fetch; empty with Ready: the spool holds everything the
	// import needs.
	Files []RelayFile
	Ready bool
	// Phase names the step for the console: head, manifests, chunks, ready.
	Phase string
	// Sequence is the release sequence the spool's verified pointer names.
	Sequence uint64
}

// Relay plan phases.
const (
	RelayPhaseHead      = "head"
	RelayPhaseManifests = "manifests"
	RelayPhaseChunks    = "chunks"
	RelayPhaseReady     = "ready"
)

// Batch caps of one round.
const (
	relayMaxFiles = 64
	relayMaxBytes = 1 << 30
)

// relayHead are the release's small files: always fetched fresh at the
// start of a cycle, unpinned (the planner and the import verify them).
var relayHead = []RelayFile{
	{Name: bundle.KeySetFile, MaxBytes: vulnbundle.MaxKeySetBytes},
	{Name: bundle.PointerFile, MaxBytes: 64 << 10},
	{Name: vulnbundle.IntelManifestFile, MaxBytes: vulnbundle.MaxManifestBytes},
	{Name: vulnbundle.AliasesManifestFile, MaxBytes: vulnbundle.MaxManifestBytes},
	{Name: vulnbundle.VulnIDsManifestFile, MaxBytes: vulnbundle.MaxManifestBytes},
}

// RelayHead is the first round of a cycle.
func RelayHead() RelayPlan {
	return RelayPlan{Files: append([]RelayFile(nil), relayHead...), Phase: RelayPhaseHead}
}

// RelayHeadNames are the head file names (refreshed every cycle).
func RelayHeadNames() []string {
	out := make([]string, 0, len(relayHead))
	for _, f := range relayHead {
		out = append(out, f.Name)
	}
	return out
}

// RelayPlan reads the spool dir (which holds a fresh head) and returns
// the files still missing for the import. An error means the head itself
// does not verify (the relay or the publisher served something the pinned
// root did not sign): the caller reports it and asks for the head again on
// the next cycle.
func (im *Importer) RelayPlan(ctx context.Context, dir string) (RelayPlan, error) {
	if im.cfg.RootKeyID == "" || im.chunks == nil {
		return RelayPlan{}, errors.New("the vulnerability feed has no pinned root or no chunk store")
	}
	st, err := im.status.GetBySource(ctx, SourceName)
	if err != nil {
		return RelayPlan{}, err
	}
	cur := readState(st.Metadata())
	cp, err := im.chunks.FeedCheckpoint().Load(ctx)
	if err != nil {
		return RelayPlan{}, err
	}
	applied := max(cur.Applied, cp.Applied)
	now := im.now()

	ksRaw, err := readCapped(dir, bundle.KeySetFile, vulnbundle.MaxKeySetBytes)
	if err != nil {
		return RelayPlan{}, fmt.Errorf("key set: %w", err)
	}
	ks, err := vulnbundle.VerifyKeySet(ksRaw, im.cfg.RootKeyID, cur.KeySetVersion, now)
	if err != nil {
		return RelayPlan{}, fmt.Errorf("key set: %w", err)
	}
	pubs := make([]ed25519.PublicKey, 0, len(ks.Keys))
	for _, k := range ks.Keys {
		pub, err := k.Decode()
		if err != nil {
			return RelayPlan{}, err
		}
		pubs = append(pubs, pub)
	}
	v := bundle.NewEd25519Verifier(pubs...)
	var p bundle.Pointer
	if err := verifiedJSON(v, dir, bundle.PointerFile, nil, bundle.PointerPayloadType(FeedV2), 64<<10, &p); err != nil {
		return RelayPlan{}, fmt.Errorf("pointer: %w", err)
	}
	if err := p.Validate(FeedV2, now, v2Limits); err != nil {
		return RelayPlan{}, fmt.Errorf("pointer: %w", err)
	}
	if p.Sequence < applied {
		return RelayPlan{}, fmt.Errorf("pointer: %w: relayed %d, applied %d", bundle.ErrRollback, p.Sequence, applied)
	}
	plan := RelayPlan{Sequence: p.Sequence}
	want := func(f RelayFile) {
		if len(plan.Files) < relayMaxFiles {
			plan.Files = append(plan.Files, f)
		}
	}

	if p.Sequence > applied {
		// The part the import will apply: the delta on exactly its base, or
		// the snapshot (the consumer's rule; a resumed bundle keeps its kind
		// and the spool keeps its files).
		ref := p.Snapshot
		if p.Delta != nil && applied != 0 && p.BaseSequence == applied {
			ref = *p.Delta
		}
		if !holds(dir, ref.Name, ref.SHA256, ref.Size) {
			plan.Phase = RelayPhaseManifests
			want(RelayFile{Name: ref.Name, SHA256: ref.SHA256, Size: ref.Size, MaxBytes: ref.Size})
		} else {
			var m bundle.Manifest
			if err := verifiedJSON(v, dir, ref.Name, &ref, bundle.ManifestPayloadType(FeedV2), ref.Size, &m); err != nil {
				return RelayPlan{}, fmt.Errorf("manifest: %w", err)
			}
			if err := m.Validate(FeedV2, now, v2Limits); err != nil {
				return RelayPlan{}, fmt.Errorf("manifest: %w", err)
			}
			var bytes int64
			for _, c := range m.Chunks() {
				name := bundle.ChunkFile(c.Ref.SHA256)
				if holdsSize(dir, name, c.Ref.Size) {
					continue
				}
				if bytes+c.Ref.Size > relayMaxBytes && len(plan.Files) > 0 {
					break
				}
				plan.Phase = RelayPhaseChunks
				bytes += c.Ref.Size
				want(RelayFile{Name: name, SHA256: c.Ref.SHA256, Size: c.Ref.Size, MaxBytes: c.Ref.Size})
			}
		}
	}
	// The side files the verified side manifests name.
	for _, f := range im.relaySideFiles(dir, ks, p.Sequence, now) {
		if !holds(dir, f.Name, f.SHA256, f.Size) {
			if plan.Phase == "" {
				plan.Phase = RelayPhaseManifests
			}
			want(RelayFile{Name: f.Name, SHA256: f.SHA256, Size: f.Size, MaxBytes: f.Size})
		}
	}
	if len(plan.Files) == 0 {
		plan.Ready, plan.Phase = true, RelayPhaseReady
	}
	return plan, nil
}

// relaySideFiles lists the data files of the side manifests that verify
// for this release (a missing or refused side manifest names none: the
// import reports it as it does for any origin).
func (im *Importer) relaySideFiles(dir string, ks *vulnbundle.KeySet, seq uint64, now time.Time) []vulnbundle.File {
	var out []vulnbundle.File
	if raw, err := readCapped(dir, vulnbundle.AliasesManifestFile, vulnbundle.MaxManifestBytes); err == nil {
		if m, err := vulnbundle.VerifyAliasManifest(ks, raw, seq, now); err == nil {
			out = append(out, m.Files...)
		}
	}
	if raw, err := readCapped(dir, vulnbundle.VulnIDsManifestFile, vulnbundle.MaxManifestBytes); err == nil {
		if m, err := vulnbundle.VerifyVulnIDsManifest(ks, raw, seq, now); err == nil {
			out = append(out, m.Files...)
		}
	}
	if im.intel != nil {
		if raw, err := readCapped(dir, vulnbundle.IntelManifestFile, vulnbundle.MaxManifestBytes); err == nil {
			if m, err := vulnbundle.VerifyIntelManifest(ks, raw, seq, now); err == nil {
				for _, s := range m.Streams {
					if _, known := intelSources[s.Name]; known {
						out = append(out, s.File)
					}
				}
			}
		}
	}
	return out
}

// RelayKeep lists the spool files the current release still needs (the
// head, the manifests the pointer pins, their chunks, the side files): the
// caller removes the rest after an import.
func (im *Importer) RelayKeep(dir string) map[string]bool {
	keep := map[string]bool{}
	for _, n := range RelayHeadNames() {
		keep[n] = true
	}
	ksRaw, err := readCapped(dir, bundle.KeySetFile, vulnbundle.MaxKeySetBytes)
	if err != nil {
		return keep
	}
	now := im.now()
	ks, err := vulnbundle.VerifyKeySet(ksRaw, im.cfg.RootKeyID, 0, now)
	if err != nil {
		return keep
	}
	pubs := make([]ed25519.PublicKey, 0, len(ks.Keys))
	for _, k := range ks.Keys {
		if pub, err := k.Decode(); err == nil {
			pubs = append(pubs, pub)
		}
	}
	v := bundle.NewEd25519Verifier(pubs...)
	var p bundle.Pointer
	if err := verifiedJSON(v, dir, bundle.PointerFile, nil, bundle.PointerPayloadType(FeedV2), 64<<10, &p); err != nil {
		return keep
	}
	refs := []bundle.FileRef{p.Snapshot}
	if p.Delta != nil {
		refs = append(refs, *p.Delta)
	}
	for _, ref := range refs {
		keep[ref.Name] = true
		var m bundle.Manifest
		if err := verifiedJSON(v, dir, ref.Name, &ref, bundle.ManifestPayloadType(FeedV2), ref.Size, &m); err != nil {
			continue
		}
		for _, c := range m.Chunks() {
			keep[bundle.ChunkFile(c.Ref.SHA256)] = true
		}
	}
	for _, f := range im.relaySideFiles(dir, ks, p.Sequence, now) {
		keep[f.Name] = true
	}
	return keep
}

// verifiedJSON reads name from dir (pinned by ref when given), verifies its
// envelope and decodes the payload into out.
func verifiedJSON(v bundle.Verifier, dir, name string, ref *bundle.FileRef, payloadType string, maxBytes int64, out any) error {
	raw, err := readCapped(dir, name, maxBytes)
	if err != nil {
		return err
	}
	if ref != nil {
		sum := sha256.Sum256(raw)
		if int64(len(raw)) != ref.Size || hex.EncodeToString(sum[:]) != ref.SHA256 {
			return fmt.Errorf("%w: %s", bundle.ErrPinMismatch, name)
		}
	}
	payload, err := v.Verify(raw, payloadType)
	if err != nil {
		return fmt.Errorf("%w: %w", bundle.ErrSignature, err)
	}
	return json.Unmarshal(payload, out)
}

func readCapped(dir, name string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(filepath.Join(dir, filepath.Base(name)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%s is over %d bytes", name, maxBytes)
	}
	return b, nil
}

// holds reports whether dir has name with exactly that digest and size.
func holds(dir, name, sha string, size int64) bool {
	if !holdsSize(dir, name, size) {
		return false
	}
	f, err := os.Open(filepath.Join(dir, filepath.Base(name)))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == sha
}

// holdsSize: a chunk's name is its digest and the spool only keeps a pinned
// file whose digest matched on receipt, so its size is enough.
func holdsSize(dir, name string, size int64) bool {
	st, err := os.Stat(filepath.Join(dir, filepath.Base(name)))
	return err == nil && st.Mode().IsRegular() && st.Size() == size
}
