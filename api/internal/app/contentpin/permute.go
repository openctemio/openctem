package contentpin

import (
	"strconv"
	"strings"
)

// Bounds of the permutations of one job.
const (
	// maxPermutations bounds the labels permutations add.
	maxPermutations = 20_000
	// maxPermBases bounds the base words crossed with environment words.
	maxPermBases = 300
	// maxIncrement is the largest number a numbered label is moved from.
	maxIncrement = 999
	// minBaseLen is the shortest base word crossed with environment words.
	minBaseLen = 3
)

// envWords are the environment words names are commonly built with. A word
// is crossed with the bases only when the organization's own names use it.
var envWords = map[string]bool{
	"dev": true, "develop": true, "test": true, "qa": true, "uat": true, "sit": true,
	"stg": true, "stage": true, "staging": true, "preprod": true, "pre": true,
	"prod": true, "prd": true, "demo": true, "beta": true, "sandbox": true,
	"int": true, "perf": true, "dr": true, "new": true, "old": true,
}

// defaultEnvs are crossed with the bases when the names use none.
var defaultEnvs = []string{"dev", "test", "uat", "staging"}

// Permutations derives likely names from learned labels (ranked, highest
// first): numbered neighbors of a numbered label ("hocviendgo5" gives
// hocviendgo6 and hocviendgo4), numbered copies of a label that ends in an
// environment word ("charts-uat" gives charts-uat1 and charts-uat2), and
// the base words crossed with the environment words the organization uses
// ("charts" and "dev" give charts-dev and dev-charts). Labels already in
// learned are not repeated. The result is deterministic for a given input
// and bounded by maxPermutations; every entry is a valid DNS label.
func Permutations(learned []string) []string {
	have := make(map[string]bool, len(learned))
	for _, l := range learned {
		have[l] = true
	}
	out := make([]string, 0, min(maxPermutations, len(learned)*2))
	add := func(l string) bool {
		if len(out) >= maxPermutations {
			return false
		}
		if !have[l] && labelRE.MatchString(l) && !allDigits(l) {
			have[l] = true
			out = append(out, l)
		}
		return true
	}
	var envs, bases []string
	for _, l := range learned {
		if strings.Contains(l, ".") {
			continue
		}
		switch {
		case envWords[l]:
			envs = append(envs, l)
		case !strings.Contains(l, "-") && len(l) >= minBaseLen && len(bases) < maxPermBases:
			bases = append(bases, l)
		}
	}
	if len(envs) == 0 {
		envs = defaultEnvs
	}
	for _, l := range learned {
		if strings.Contains(l, ".") {
			continue
		}
		for _, n := range neighbors(l) {
			if !add(n) {
				return out
			}
		}
	}
	for _, b := range bases {
		for _, e := range envs {
			if !add(b+"-"+e) || !add(e+"-"+b) {
				return out
			}
		}
	}
	return out
}

// neighbors are the numbered variants of one label.
func neighbors(l string) []string {
	i := len(l)
	for i > 0 && l[i-1] >= '0' && l[i-1] <= '9' {
		i--
	}
	prefix, digits := l[:i], l[i:]
	if digits != "" {
		n, err := strconv.Atoi(digits)
		if err != nil || n > maxIncrement || prefix == "" {
			return nil
		}
		width := len(digits)
		pad := func(v int) string {
			s := strconv.Itoa(v)
			for len(s) < width {
				s = "0" + s
			}
			return s
		}
		out := []string{prefix + pad(n+1)}
		if n > 0 {
			out = append(out, prefix+pad(n-1))
		}
		return out
	}
	if j := strings.LastIndexByte(l, '-'); j > 0 && envWords[l[j+1:]] {
		return []string{l + "1", l + "2"}
	}
	return nil
}
