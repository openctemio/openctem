package email

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"
)

// nowFunc is the clock of the Date header; tests replace it.
var nowFunc = time.Now

// reservedHeaders are written by buildMessage itself. A custom header with
// one of these names is dropped, so a caller cannot send two Date or
// Content-Type headers.
var reservedHeaders = map[string]bool{
	"from": true, "to": true, "subject": true, "reply-to": true, "date": true,
	"message-id": true, "mime-version": true, "content-type": true,
	"content-transfer-encoding": true, "cc": true, "bcc": true,
}

// buildMessage builds the RFC 5322 message: Date and Message-ID headers,
// RFC 2047 encoded Subject and display name, and a body that is plain text, or
// multipart/alternative (text and HTML), or multipart/related when the HTML
// carries inline images. Bodies are quoted-printable, so no line exceeds the
// 998-octet limit. Every header value passes through SanitizeHeaderValue
// before it is encoded, so a CR or LF cannot start another header.
func (s *SMTPSender) buildMessage(msg *Message) []byte {
	var b bytes.Buffer
	safeFrom := SanitizeHeaderValue(s.config.From)

	b.WriteString("From: " + formatAddress(SanitizeHeaderValue(s.config.FromName), safeFrom) + "\r\n")

	to := make([]string, 0, len(msg.To))
	for _, r := range msg.To {
		to = append(to, SanitizeHeaderValue(r))
	}
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString(foldedHeader("Subject", encodeHeaderText(SanitizeHeaderValue(msg.Subject))) + "\r\n")
	if msg.ReplyTo != "" {
		b.WriteString("Reply-To: " + SanitizeHeaderValue(msg.ReplyTo) + "\r\n")
	}
	b.WriteString("Date: " + nowFunc().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: " + newMessageID(safeFrom) + "\r\n")

	custom := make(map[string]string, len(msg.Headers))
	keys := make([]string, 0, len(msg.Headers))
	for k, v := range msg.Headers {
		key := strings.TrimSpace(SanitizeHeaderValue(k))
		if key == "" || strings.ContainsAny(key, ": \t") || reservedHeaders[strings.ToLower(key)] {
			continue
		}
		custom[key] = encodeHeaderText(SanitizeHeaderValue(v))
		keys = append(keys, key)
	}
	// RFC 3834: automatic replies (out-of-office) must not answer this mail.
	hasAuto := false
	for _, k := range keys {
		if strings.EqualFold(k, "Auto-Submitted") {
			hasAuto = true
		}
	}
	if !hasAuto {
		b.WriteString("Auto-Submitted: auto-generated\r\n")
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(k + ": " + custom[k] + "\r\n")
	}

	b.WriteString("MIME-Version: 1.0\r\n")
	switch {
	case !msg.IsHTML:
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		writeQP(&b, msg.Body)
	case len(msg.Inline) > 0:
		writeRelated(&b, msg)
	default:
		writeAlternative(&b, msg)
	}
	return b.Bytes()
}

// formatAddress renders a From value. A display name is quoted when it needs
// it and RFC 2047 encoded when it is not ASCII.
func formatAddress(name, addr string) string {
	if name == "" {
		return addr
	}
	return (&mail.Address{Name: name, Address: addr}).String()
}

// encodeHeaderText RFC 2047 encodes an unstructured header value that holds
// non-ASCII text. ASCII values pass through unchanged.
func encodeHeaderText(v string) string {
	return mime.QEncoding.Encode("UTF-8", v)
}

// foldedHeader renders "Name: value", wrapped at whitespace so no line
// exceeds 76 characters where the value allows it (RFC 5322 section 2.2.3).
// Encoded words are separated by a space, which is where the fold goes.
func foldedHeader(name, v string) string {
	var out strings.Builder
	out.WriteString(name + ":")
	line := len(name) + 1
	for _, w := range strings.Split(v, " ") {
		if line+1+len(w) > 76 && line > 1 {
			out.WriteString("\r\n ")
			line = 1
		} else {
			out.WriteString(" ")
			line++
		}
		out.WriteString(w)
		line += len(w)
	}
	return out.String()
}

// newMessageID returns a unique Message-ID on the domain of the From address
// (RFC 5322 section 3.6.4).
func newMessageID(from string) string {
	domain := "localhost"
	if i := strings.LastIndex(from, "@"); i >= 0 {
		var d strings.Builder
		for _, r := range from[i+1:] {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
				d.WriteRune(r)
			}
		}
		if d.Len() > 0 {
			domain = d.String()
		}
	}
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		// crypto/rand does not fail on supported platforms; the clock
		// still makes the id unique enough for a log reference.
		sum := sha256.Sum256([]byte(nowFunc().String()))
		copy(rnd[:], sum[:])
	}
	return "<" + hex.EncodeToString(rnd[:]) + "@" + domain + ">"
}

// writeQP writes s quoted-printable: lines wrapped at 76 characters with soft
// breaks, line endings CRLF.
func writeQP(b *bytes.Buffer, s string) {
	w := quotedprintable.NewWriter(b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	if !bytes.HasSuffix(b.Bytes(), []byte("\n")) {
		b.WriteString("\r\n")
	}
}

func boundaryFor(kind string, msg *Message) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + msg.Body + "\x00" + msg.TextBody))
	return "oc-" + kind + "-" + hex.EncodeToString(sum[:8])
}

func textAlternative(msg *Message) string {
	if msg.TextBody != "" {
		return msg.TextBody
	}
	return HTMLToText(msg.Body)
}

// writeAlternativeParts writes the text and HTML parts of an alternative.
func writeAlternativeParts(b *bytes.Buffer, boundary string, msg *Message) {
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	writeQP(b, textAlternative(msg))
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	writeQP(b, msg.Body)
	b.WriteString("--" + boundary + "--\r\n")
}

// writeAlternative writes a multipart/alternative message: text, then HTML
// (the last part is the preferred one).
func writeAlternative(b *bytes.Buffer, msg *Message) {
	boundary := boundaryFor("alt", msg)
	b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
	writeAlternativeParts(b, boundary, msg)
}

// writeRelated writes the alternative with its inline images as one
// multipart/related message. The boundaries are derived from the content, and
// the Content-IDs come from constants.
func writeRelated(b *bytes.Buffer, msg *Message) {
	boundary := boundaryFor("rel", msg)
	alt := boundaryFor("alt", msg)
	b.WriteString("Content-Type: multipart/related; boundary=\"" + boundary + "\"\r\n\r\n")
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: multipart/alternative; boundary=\"" + alt + "\"\r\n\r\n")
	writeAlternativeParts(b, alt, msg)
	for _, img := range msg.Inline {
		cid := SanitizeHeaderValue(img.CID)
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: " + SanitizeHeaderValue(img.ContentType) + "\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n")
		b.WriteString("Content-ID: <" + cid + ">\r\n")
		b.WriteString("Content-Disposition: inline; filename=\"" + cid + ".png\"\r\n\r\n")
		enc := base64.StdEncoding.EncodeToString(img.Data)
		for len(enc) > 76 {
			b.WriteString(enc[:76] + "\r\n")
			enc = enc[76:]
		}
		b.WriteString(enc + "\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
}

var (
	reHiddenBlocks = regexp.MustCompile(`(?is)<(head|style|script)\b.*?</(head|style|script)\s*>`)
	reLink         = regexp.MustCompile(`(?is)<a\b[^>]*?href\s*=\s*["']([^"']*)["'][^>]*>(.*?)</a\s*>`)
	reBreak        = regexp.MustCompile(`(?i)<br\s*/?>|</(div|tr|li)\s*>`)
	reParagraph    = regexp.MustCompile(`(?i)</(p|h[1-6]|table)\s*>`)
	reTag          = regexp.MustCompile(`(?s)<[^>]*>`)
	reSpaces       = regexp.MustCompile(`[ \t\r\f\v]+`)
	reBlankLines   = regexp.MustCompile(`\n[ ]*(\n[ ]*)+`)
)

// HTMLToText renders an HTML body as the text/plain alternative of a message:
// block ends become line breaks, a link keeps its target in parentheses (a
// set-password link must stay usable in the text part), and tags and entities
// are removed.
func HTMLToText(h string) string {
	h = reHiddenBlocks.ReplaceAllString(h, "")
	h = reLink.ReplaceAllStringFunc(h, func(m string) string {
		sm := reLink.FindStringSubmatch(m)
		label := strings.TrimSpace(reTag.ReplaceAllString(sm[2], ""))
		href := strings.TrimSpace(html.UnescapeString(sm[1]))
		if href == "" || label == href || strings.HasPrefix(strings.ToLower(href), "mailto:") && label == strings.TrimPrefix(href, "mailto:") {
			return label
		}
		return fmt.Sprintf("%s (%s)", label, href)
	})
	h = reBreak.ReplaceAllString(h, "\n")
	h = reParagraph.ReplaceAllString(h, "\n\n")
	h = reTag.ReplaceAllString(h, "")
	h = html.UnescapeString(h)
	lines := strings.Split(reSpaces.ReplaceAllString(h, " "), "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	h = reBlankLines.ReplaceAllString(strings.Join(lines, "\n"), "\n\n")
	return strings.TrimSpace(h) + "\n"
}
