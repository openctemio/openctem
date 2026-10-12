package attachment

import (
	"mime"
	"net/http"
	"path/filepath"
	"strings"
)

// SniffLen is how many leading bytes DetectContentType looks at.
const SniffLen = 512

// extensionTypes refine a generic sniffed type for formats the content
// sniffer has no signature for. They can only turn "text/plain" or
// "application/octet-stream" into one of these, never upgrade content to an
// active type (HTML, SVG, script).
var extensionTypes = map[string]string{
	".md": "text/markdown", ".markdown": "text/markdown",
	".csv": "text/csv", ".har": "application/har+json",
	".mp4": "video/mp4", ".webm": "video/webm",
}

// DetectContentType is the media type of an upload, decided from its first
// bytes (head, up to SniffLen) and, only where the content is generic text or
// binary, from the file name's extension. What the client declares is never
// used: a declared type lets an HTML page through as "image/png". The result
// has no parameters, so it can be compared with an allow-list.
func DetectContentType(head []byte, filename string) string {
	if len(head) > SniffLen {
		head = head[:SniffLen]
	}
	ct := http.DetectContentType(head)
	if mt, _, err := mime.ParseMediaType(ct); err == nil {
		ct = mt
	}
	if ct == "application/octet-stream" || ct == "text/plain" {
		if better, ok := extensionTypes[strings.ToLower(filepath.Ext(filename))]; ok {
			ct = better
		}
	}
	return ct
}
