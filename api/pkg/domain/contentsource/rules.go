package contentsource

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
)

// MaxRules bounds the rule list recorded for one snapshot.
const MaxRules = 50000

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// FileIndexOf lists a canonical archive's files with their hashes.
func FileIndexOf(files []contentpack.File) []FileEntry {
	out := make([]FileEntry, 0, len(files))
	for _, f := range files {
		out = append(out, FileEntry{Path: f.Path, SHA256: sha(f.Data), Size: int64(len(f.Data))})
	}
	return out
}

func isYAML(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	return ext == ".yaml" || ext == ".yml"
}

// ExtractRules lists the rules of a snapshot's files, each with the hash of
// its own definition: every rule of a semgrep rules file, every nuclei
// template (by its id) and, for a wordlist, every file (by its path).
// duplicate is true when two definitions share an id. Files that do not
// parse are skipped here; lint reports them.
func ExtractRules(kind Kind, files []contentpack.File) (rules []Rule, duplicate bool) {
	seen := map[string]bool{}
	add := func(r Rule) {
		if seen[r.ID] {
			duplicate = true
			return
		}
		if len(rules) >= MaxRules {
			return
		}
		seen[r.ID] = true
		rules = append(rules, r)
	}
	for _, f := range files {
		switch kind {
		case KindWordlist:
			add(Rule{ID: f.Path, SHA256: sha(f.Data), Path: f.Path})
		case KindSemgrepRules:
			if !isYAML(f.Path) {
				continue
			}
			for _, r := range semgrepRules(f) {
				add(r)
			}
		case KindNucleiTemplates:
			if !isYAML(f.Path) {
				continue
			}
			if id := nucleiID(f.Data); id != "" {
				add(Rule{ID: id, SHA256: sha(f.Data), Path: f.Path})
			}
		}
	}
	if rules == nil {
		rules = []Rule{}
	}
	return rules, duplicate
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func document(data []byte) *yaml.Node {
	var doc yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&doc); err != nil {
		return nil
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil
	}
	return doc.Content[0]
}

func semgrepRules(f contentpack.File) []Rule {
	list := mappingValue(document(f.Data), "rules")
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]Rule, 0, len(list.Content))
	for _, item := range list.Content {
		id := mappingValue(item, "id")
		if id == nil || id.Kind != yaml.ScalarNode || strings.TrimSpace(id.Value) == "" {
			continue
		}
		def, err := yaml.Marshal(item)
		if err != nil {
			continue
		}
		out = append(out, Rule{ID: strings.TrimSpace(id.Value), SHA256: sha(def), Path: f.Path})
	}
	return out
}

func nucleiID(data []byte) string {
	id := mappingValue(document(data), "id")
	if id == nil || id.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(id.Value)
}

// DetectLicense names the license of a LICENSE file: an SPDX id for the
// common open licenses, a LicenseRef for licenses that forbid use as a
// service, "" when unknown.
func DetectLicense(text []byte) string {
	t := strings.ToLower(string(text))
	switch {
	case len(t) == 0:
		return ""
	case strings.Contains(t, "semgrep rules license"):
		return "LicenseRef-Semgrep-Rules"
	case strings.Contains(t, "commons clause"):
		return "LicenseRef-Commons-Clause"
	case strings.Contains(t, "apache license") && strings.Contains(t, "version 2.0"):
		return "Apache-2.0"
	case strings.Contains(t, "mit license") || strings.Contains(t, "permission is hereby granted, free of charge"):
		return "MIT"
	case strings.Contains(t, "gnu lesser general public license"):
		return "LGPL"
	case strings.Contains(t, "gnu affero general public license"):
		return "AGPL-3.0"
	case strings.Contains(t, "gnu general public license"):
		return "GPL"
	case strings.Contains(t, "mozilla public license"):
		return "MPL-2.0"
	case strings.Contains(t, "redistribution and use in source and binary forms"):
		return "BSD"
	}
	return "LicenseRef-Unknown"
}
