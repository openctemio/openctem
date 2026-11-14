package aibundle

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/openctem/server/internal/app/aipolicy"
)

// ShortenedMark ends a field value the platform shortened so the bundle fits
// a job.
const ShortenedMark = " [shortened by the platform]"

// minShortenedRunes is the shortest a value is cut to before the field is
// left out instead.
const minShortenedRunes = 64

// Fit makes the bundle's text satisfy fits (a job's size limit, measured on
// the text as it will be encoded), in this order: knowledge excerpts are
// left out from the last one, then the longest field values are shortened
// (ending in ShortenedMark), and a field that cannot be shortened enough is
// left out and listed as withheld. Every change is said in the text itself
// (a platform fact), the digest is computed again, and the fields shortened
// are returned so the caller can record them. ok is false when even the
// smallest bundle does not fit.
//
// A bundle that already fits is not changed.
func (bd *Bundle) Fit(fits func(text string) bool) (shortened []aipolicy.Field, ok bool) {
	if fits(bd.Text) {
		return nil, true
	}
	rerender := func() {
		text, hit := render(bd, bd.InjectionSuspected)
		bd.Text, bd.InjectionSuspected = text, bd.InjectionSuspected || hit
	}
	if len(bd.Knowledge) > 0 {
		bd.Facts = append(bd.Facts, "The platform left out organization knowledge to fit the job.")
	}
	for len(bd.Knowledge) > 0 {
		bd.Knowledge = bd.Knowledge[:len(bd.Knowledge)-1]
		bd.KnowledgeRefs = bd.KnowledgeRefs[:0]
		for _, k := range bd.Knowledge {
			bd.KnowledgeRefs = append(bd.KnowledgeRefs, "kb:"+strconv.Itoa(k.Ordinal))
		}
		rerender()
		if fits(bd.Text) {
			bd.Digest = digest(bd.Fields, bd.Facts, bd.Knowledge)
			return nil, true
		}
	}
	for !fits(bd.Text) {
		i := bd.longestField()
		if i < 0 {
			bd.Digest = digest(bd.Fields, bd.Facts, bd.Knowledge)
			return shortened, false
		}
		name := bd.Fields[i].Name
		fact := "The platform shortened the value of " + string(name) + " to fit the job."
		bd.Facts = append(bd.Facts, fact)
		if keep := bd.longestKeep(i, fits); keep >= minShortenedRunes {
			bd.Fields[i].Value = string([]rune(bd.Fields[i].Value)[:keep]) + ShortenedMark
			shortened = append(shortened, name)
			rerender()
			continue
		}
		// Too little would be left: the field is withheld instead.
		bd.Facts[len(bd.Facts)-1] = "The platform left out " + string(name) + " to fit the job."
		bd.Fields = append(bd.Fields[:i], bd.Fields[i+1:]...)
		bd.FieldsWithheld = append(bd.FieldsWithheld, name)
		for j, f := range bd.FieldsSent {
			if f == name {
				bd.FieldsSent = append(bd.FieldsSent[:j], bd.FieldsSent[j+1:]...)
				break
			}
		}
		rerender()
	}
	bd.Digest = digest(bd.Fields, bd.Facts, bd.Knowledge)
	return shortened, true
}

// longestField is the index of the field with the longest value that was
// not shortened yet, or -1.
func (bd *Bundle) longestField() int {
	best, n := -1, 0
	for i, f := range bd.Fields {
		if l := utf8.RuneCountInString(f.Value); l > n && !strings.HasSuffix(f.Value, ShortenedMark) {
			best, n = i, l
		}
	}
	return best
}

// longestKeep is the most runes of field i's value that may stay so the text
// fits (binary search; each probe renders the text), or 0.
func (bd *Bundle) longestKeep(i int, fits func(string) bool) int {
	orig := bd.Fields[i].Value
	r := []rune(orig)
	lo, hi := 0, len(r)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		bd.Fields[i].Value = string(r[:mid]) + ShortenedMark
		text, _ := render(bd, false)
		if fits(text) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	bd.Fields[i].Value = orig
	return lo
}
