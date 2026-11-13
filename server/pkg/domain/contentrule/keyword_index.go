package contentrule

// keywordIndex finds every keyword of a set of matchers in a lower-cased
// text in one pass: each position's first three bytes are looked up in a
// small bitset, then in a map of the keywords starting with them. Keywords
// are at least MinKeywordLen (3) bytes, so every keyword has a trigram.
type keywordIndex struct {
	keywords []string
	matchers [][]*compiledMatcher
	byTri    map[uint32][]int
	bits     [1 << 16 / 64]uint64
}

func trigram(b []byte) uint32 { return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]) }

func triBit(t uint32) uint32 { return (t ^ t>>11 ^ t>>5) & (1<<16 - 1) }

func newKeywordIndex(ms []*compiledMatcher) *keywordIndex {
	ix := &keywordIndex{byTri: map[uint32][]int{}}
	pos := map[string]int{}
	for _, m := range ms {
		for _, k := range m.keywords {
			if len(k) < MinKeywordLen {
				continue
			}
			i, ok := pos[k]
			if !ok {
				i = len(ix.keywords)
				pos[k] = i
				ix.keywords = append(ix.keywords, k)
				ix.matchers = append(ix.matchers, nil)
				t := trigram([]byte(k))
				ix.byTri[t] = append(ix.byTri[t], i)
				b := triBit(t)
				ix.bits[b/64] |= 1 << (b % 64)
			}
			if !containsMatcher(ix.matchers[i], m) {
				ix.matchers[i] = append(ix.matchers[i], m)
			}
		}
	}
	return ix
}

func containsMatcher(ms []*compiledMatcher, m *compiledMatcher) bool {
	for _, x := range ms {
		if x == m {
			return true
		}
	}
	return false
}

// walk calls fn for each keyword hit (keyword index, offset) in order of
// offset, at most maxHitsPerKeyword per keyword; fn returns false to stop.
func (ix *keywordIndex) walk(lower []byte, fn func(kw, pos int) bool) {
	hits := make([]int, len(ix.keywords))
	for p := 0; p+MinKeywordLen <= len(lower); p++ {
		t := trigram(lower[p:])
		b := triBit(t)
		if ix.bits[b/64]&(1<<(b%64)) == 0 {
			continue
		}
		for _, k := range ix.byTri[t] {
			kw := ix.keywords[k]
			if hits[k] >= maxHitsPerKeyword || p+len(kw) > len(lower) || string(lower[p:p+len(kw)]) != kw {
				continue
			}
			hits[k]++
			if !fn(k, p) {
				return
			}
		}
	}
}
