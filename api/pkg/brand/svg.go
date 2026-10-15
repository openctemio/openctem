package brand

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	svgNS   = "http://www.w3.org/2000/svg"
	xlinkNS = "http://www.w3.org/1999/xlink"
	xmlNS   = "http://www.w3.org/XML/1998/namespace"

	maxSVGDepth    = 64
	maxSVGElements = 10000
)

// svgElements are the drawing elements a logo may use. Anything else
// (script, foreignObject, image, a, animation, editor metadata) is either
// refused or dropped with its content.
var svgElements = map[string]bool{
	"svg": true, "g": true, "path": true, "rect": true, "circle": true, "ellipse": true,
	"line": true, "polyline": true, "polygon": true, "defs": true, "linearGradient": true,
	"radialGradient": true, "stop": true, "title": true, "desc": true, "clipPath": true,
	"mask": true, "use": true, "symbol": true, "text": true, "tspan": true, "style": true,
	"pattern": true, "filter": true, "feGaussianBlur": true, "feOffset": true, "feBlend": true,
	"feColorMatrix": true, "feFlood": true, "feComposite": true, "feMerge": true, "feMergeNode": true,
}

// svgForbidden are elements that can run script, load other content or
// change the document over time. Their presence is an error, not something
// to strip silently: the operator should know the file was unsafe.
var svgForbidden = map[string]bool{
	"script": true, "foreignObject": true, "iframe": true, "object": true, "embed": true,
	"image": true, "a": true, "animate": true, "animateMotion": true, "animateTransform": true,
	"set": true, "handler": true, "listener": true, "audio": true, "video": true, "feImage": true,
}

// ErrUnsafeSVG wraps every reason an SVG is refused.
var ErrUnsafeSVG = errors.New("unsafe SVG")

// SanitizeSVG returns the drawing of an SVG with nothing that can run
// script or fetch content: no DOCTYPE or entities, no script-capable or
// loading elements, no event-handler attributes, only same-document
// references, and style without imports or external URLs. Unknown
// elements and attributes from other namespaces (editor metadata) are
// dropped. The output is rebuilt from the allowed parts, never echoed.
func SanitizeSVG(data []byte) ([]byte, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true
	var out bytes.Buffer
	depth, skip, elements := 0, 0, 0
	sawRoot := false
	var stack []string
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: not well-formed XML: %w", ErrUnsafeSVG, err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			// <!DOCTYPE …> can declare entities (expansion, external files).
			return nil, fmt.Errorf("%w: DOCTYPE and entity declarations are not allowed", ErrUnsafeSVG)
		case xml.StartElement:
			elements++
			depth++
			if elements > maxSVGElements || depth > maxSVGDepth {
				return nil, fmt.Errorf("%w: too many or too deeply nested elements", ErrUnsafeSVG)
			}
			name := t.Name.Local
			if svgForbidden[name] {
				return nil, fmt.Errorf("%w: element <%s> is not allowed", ErrUnsafeSVG, name)
			}
			if !sawRoot {
				if name != "svg" || (t.Name.Space != "" && t.Name.Space != svgNS) {
					return nil, fmt.Errorf("%w: the root element is not <svg>", ErrUnsafeSVG)
				}
				sawRoot = true
			}
			if skip > 0 || !svgElements[name] || (t.Name.Space != "" && t.Name.Space != svgNS) {
				skip++
				continue
			}
			if err := writeStart(&out, t, depth == 1); err != nil {
				return nil, err
			}
			stack = append(stack, name)
		case xml.EndElement:
			depth--
			if skip > 0 {
				skip--
				continue
			}
			name := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			out.WriteString("</" + name + ">")
		case xml.CharData:
			if skip > 0 || len(stack) == 0 {
				continue
			}
			if stack[len(stack)-1] == "style" {
				if err := checkCSS(string(t)); err != nil {
					return nil, err
				}
			}
			_ = xml.EscapeText(&out, t)
		case xml.Comment, xml.ProcInst:
			// Dropped.
		}
	}
	if !sawRoot {
		return nil, fmt.Errorf("%w: no <svg> element", ErrUnsafeSVG)
	}
	return out.Bytes(), nil
}

func writeStart(out *bytes.Buffer, t xml.StartElement, root bool) error {
	out.WriteString("<" + t.Name.Local)
	if root {
		out.WriteString(` xmlns="` + svgNS + `" xmlns:xlink="` + xlinkNS + `"`)
	}
	for _, a := range t.Attr {
		name, ok, err := svgAttr(t.Name.Local, a)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		out.WriteString(" " + name + `="`)
		_ = xml.EscapeText(out, []byte(a.Value))
		out.WriteString(`"`)
	}
	out.WriteString(">")
	return nil
}

// svgAttr decides one attribute: its output name, or false to drop it, or
// an error when it is unsafe.
func svgAttr(elem string, a xml.Attr) (string, bool, error) {
	local := a.Name.Local
	var name string
	switch a.Name.Space {
	case "":
		name = local
	case xlinkNS:
		name = "xlink:" + local
	case xmlNS:
		name = "xml:" + local
	default:
		return "", false, nil // xmlns declarations (rewritten) and editor namespaces
	}
	if local == "xmlns" {
		return "", false, nil
	}
	lower := strings.ToLower(local)
	if strings.HasPrefix(lower, "on") {
		return "", false, fmt.Errorf("%w: event handler attribute %s on <%s>", ErrUnsafeSVG, local, elem)
	}
	if lower == "href" || lower == "src" || lower == "action" || lower == "formaction" {
		if !strings.HasPrefix(strings.TrimSpace(a.Value), "#") {
			return "", false, fmt.Errorf("%w: <%s> refers outside the image (%s)", ErrUnsafeSVG, elem, name)
		}
	}
	if err := checkCSS(a.Value); err != nil {
		return "", false, err
	}
	return name, true, nil
}

// checkCSS refuses style text and attribute values that import or fetch
// content, or carry script.
func checkCSS(v string) error {
	l := strings.ToLower(strings.Join(strings.Fields(v), ""))
	for _, bad := range []string{"@import", "javascript:", "vbscript:", "data:", "expression(", "behavior:", "-moz-binding", "<"} {
		if strings.Contains(l, bad) {
			return fmt.Errorf("%w: %q is not allowed", ErrUnsafeSVG, bad)
		}
	}
	for i := strings.Index(l, "url("); i >= 0; {
		rest := strings.TrimLeft(l[i+4:], `'"`)
		if !strings.HasPrefix(rest, "#") {
			return fmt.Errorf("%w: url() must refer to an element of the image", ErrUnsafeSVG)
		}
		next := strings.Index(l[i+4:], "url(")
		if next < 0 {
			break
		}
		i += 4 + next
	}
	return nil
}
