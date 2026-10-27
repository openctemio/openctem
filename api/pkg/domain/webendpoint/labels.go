package webendpoint

import (
	"path"
	"strings"

	"github.com/openctemio/ctis"
)

// Labels the platform sets on an endpoint when it stores it (research: web
// content intelligence, "extension classes" and "login surface"). They are
// computed from the path template and the parameter names only. A person may
// add or remove labels; the platform adds its own again only when a later
// sighting still matches.
const (
	// LabelAuthLogin marks an endpoint that takes a password field.
	LabelAuthLogin = "auth:login"
	labelExtPrefix = "ext:"
)

// Extension classes (the part after "ext:").
const (
	ExtBackup  = "backup"
	ExtConfig  = "config"
	ExtArchive = "archive"
	ExtDBDump  = "dbdump"
	ExtSource  = "source"
	ExtLog     = "log"
)

var extClasses = map[string]string{
	".bak": ExtBackup, ".old": ExtBackup, ".orig": ExtBackup, ".save": ExtBackup, ".swp": ExtBackup,
	".backup": ExtBackup, ".copy": ExtBackup, ".tmp": ExtBackup,
	".env": ExtConfig, ".conf": ExtConfig, ".config": ExtConfig, ".ini": ExtConfig, ".yml": ExtConfig,
	".yaml": ExtConfig, ".properties": ExtConfig, ".toml": ExtConfig, ".cfg": ExtConfig,
	".zip": ExtArchive, ".tar": ExtArchive, ".gz": ExtArchive, ".tgz": ExtArchive, ".rar": ExtArchive,
	".7z": ExtArchive, ".bz2": ExtArchive, ".xz": ExtArchive,
	".sql": ExtDBDump, ".sqlite": ExtDBDump, ".sqlite3": ExtDBDump, ".db": ExtDBDump, ".mdb": ExtDBDump, ".dump": ExtDBDump,
	".py": ExtSource, ".rb": ExtSource, ".java": ExtSource, ".go": ExtSource, ".cs": ExtSource,
	".inc": ExtSource, ".phps": ExtSource, ".pl": ExtSource, ".sh": ExtSource, ".c": ExtSource, ".cpp": ExtSource,
	".log": ExtLog, ".trace": ExtLog,
}

// ExtLabel returns the "ext:<class>" label of a path template's file
// extension, or "". A trailing "~" (an editor backup) is a backup. The
// extension is read from the last segment and compared case-insensitively.
func ExtLabel(template string) string {
	base := path.Base(strings.ToLower(template))
	if base == "." || base == "/" {
		return ""
	}
	if strings.HasSuffix(base, "~") && len(base) > 1 {
		return labelExtPrefix + ExtBackup
	}
	ext := path.Ext(base)
	if c, ok := extClasses[ext]; ok {
		return labelExtPrefix + c
	}
	return ""
}

// passwordNames are the parameter names of a password field.
var passwordNames = map[string]bool{"password": true, "passwd": true, "pwd": true, "pass": true, "passcode": true}

// IsLoginParams reports whether the parameters include a password field: a
// parameter whose type hint is "password", or a form parameter named like a
// password. Query parameters named password do not mark a login form.
func IsLoginParams(params []ParamObservation) bool {
	for _, p := range params {
		if p.TypeHint == "password" {
			return true
		}
		if p.Location == string(ctis.ParamLocationForm) && passwordNames[normParamName(p.Name)] {
			return true
		}
	}
	return false
}

// platformLabels computes the labels an observation gets at ingest.
func platformLabels(template string, params []ParamObservation) []string {
	var out []string
	if l := ExtLabel(template); l != "" {
		out = append(out, l)
	}
	if IsLoginParams(params) {
		out = append(out, LabelAuthLogin)
	}
	return out
}
