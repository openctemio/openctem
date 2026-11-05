package contentrule

// Template facts (docs/architecture/template-facts.md): the mapping that
// routes the info matches of template scanners to asset facts. It is a
// platform content pack of kind template-facts on the stable channel,
// signed like every platform pack; the embedded template-facts-core pack is
// installed on first start and is the fallback when no stable pack can be
// read.

import (
	"context"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/contentrule/builtin"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/templatefact"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// BuiltinTemplateFacts is the embedded template facts mapping.
func BuiltinTemplateFacts() (*templatefact.Map, error) { return builtin.TemplateFacts() }

// TemplateFacts is the mapping of the stable template facts packs (in pack
// name order; an entry id another pack already defined is skipped), or the
// embedded one when none is on a stable channel or none can be read. Never
// nil when the embedded pack is valid.
func (s *Service) TemplateFacts(ctx context.Context) *templatefact.Map {
	fallback, _ := BuiltinTemplateFacts()
	if s == nil || s.platform == nil {
		return fallback
	}
	chans, err := s.stableChannels(ctx, s.now())
	if err != nil {
		s.log.Warn("template facts: channels not read; using the embedded mapping", "error", logger.SanitizeError(err))
		return fallback
	}
	type loaded struct {
		origin  string
		entries []templatefact.Entry
	}
	var packs []loaded
	var key strings.Builder
	for _, c := range chans {
		entries, origin := s.factsPack(ctx, c)
		if len(entries) == 0 {
			continue
		}
		packs = append(packs, loaded{origin: origin, entries: entries})
		key.WriteString(c.Digest + ",")
	}
	if len(packs) == 0 {
		return fallback
	}
	s.mu.Lock()
	if s.factsMap != nil && s.factsKey == key.String() {
		m := s.factsMap
		s.mu.Unlock()
		return m
	}
	s.mu.Unlock()
	sort.Slice(packs, func(i, j int) bool { return packs[i].origin < packs[j].origin })
	seen := map[string]bool{}
	var all []templatefact.Entry
	origins := make([]string, 0, len(packs))
	for _, p := range packs {
		origins = append(origins, p.origin)
		for _, e := range p.entries {
			if !seen[e.ID] {
				seen[e.ID] = true
				all = append(all, e)
			}
		}
	}
	m, err := templatefact.Compile(strings.Join(origins, ","), all)
	if err != nil {
		s.log.Warn("template facts: stable packs do not compile; using the embedded mapping", "error", logger.SanitizeError(err))
		return fallback
	}
	s.mu.Lock()
	s.factsMap, s.factsKey = m, key.String()
	s.mu.Unlock()
	return m
}

// factsPack reads the template facts entries of the pack a stable channel
// names (none for a pack of another kind), parsed once per digest. A pack
// that cannot be read is skipped and logged.
func (s *Service) factsPack(ctx context.Context, c dom.ChannelPointer) ([]templatefact.Entry, string) {
	s.mu.Lock()
	entries, ok := s.facts[c.Digest]
	s.mu.Unlock()
	origin := c.Name
	if ok {
		return entries, origin
	}
	meta, data, err := s.platform.Archive(ctx, c.PackID.String())
	if err != nil {
		s.log.Warn("template facts pack not read", "pack", c.Name, "error", logger.SanitizeError(err))
		return nil, origin
	}
	if meta.Kind == dom.KindTemplateFacts {
		arc, err := dom.ReadPlatformCanonical(data, meta.Digest)
		if err != nil {
			s.log.Warn("template facts pack not read", "pack", c.Name, "error", logger.SanitizeError(err))
			return nil, origin
		}
		for _, f := range arc.Files {
			if !strings.HasSuffix(f.Path, ".yaml") && !strings.HasSuffix(f.Path, ".yml") {
				continue
			}
			e, err := templatefact.ParseFile(f.Data)
			if err != nil {
				continue // lint refused such a file at ingest
			}
			entries = append(entries, e...)
		}
	}
	s.mu.Lock()
	s.facts[c.Digest] = entries
	s.mu.Unlock()
	return entries, origin
}
