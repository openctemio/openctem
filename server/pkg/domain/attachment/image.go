package attachment

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	_ "image/gif"  // DecodeConfig for GIF
	_ "image/jpeg" // DecodeConfig for JPEG
	_ "image/png"  // DecodeConfig for PNG
)

// Image hygiene for uploaded evidence (api/docs/rfcs/RFC-084-file-storage.md):
// metadata that can identify a person or place (EXIF with GPS, XMP, IPTC,
// comments, text chunks) is removed without touching the pixels, and an
// image whose dimensions would decode to an oversized bitmap is refused.

// MaxImagePixels is the largest width × height accepted for an image
// (50 megapixels): a small file can declare a huge canvas that a viewer or
// the report renderer would allocate in full.
const MaxImagePixels = 50_000_000

// ErrImageTooLarge: the image's dimensions pass MaxImagePixels.
var ErrImageTooLarge = errors.New("image dimensions exceed the pixel limit")

// ErrImageInvalid: the image's structure cannot be read.
var ErrImageInvalid = errors.New("image is malformed")

// IsImageType reports whether ct is a raster image type the hygiene applies to.
func IsImageType(ct string) bool { return isImageContentType(ct) }

// SanitizeImage returns the image without its metadata, after checking its
// dimensions. ct is the sniffed type. The pixels and what is needed to show
// them (color profile, transparency, animation, JPEG orientation) are kept.
func SanitizeImage(data []byte, ct string) ([]byte, error) {
	w, h, err := imageDimensions(data, ct)
	if err != nil {
		return nil, err
	}
	if w <= 0 || h <= 0 {
		return nil, ErrImageInvalid
	}
	if int64(w)*int64(h) > MaxImagePixels {
		return nil, fmt.Errorf("%w: %dx%d is more than %d pixels", ErrImageTooLarge, w, h, MaxImagePixels)
	}
	switch ct {
	case "image/jpeg":
		return stripJPEG(data)
	case "image/png":
		return stripPNG(data)
	case "image/gif":
		return stripGIF(data)
	case "image/webp":
		return stripWebP(data)
	}
	return nil, ErrImageInvalid
}

func imageDimensions(data []byte, ct string) (int, int, error) {
	if ct == "image/webp" {
		return webpDimensions(data)
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return 0, 0, fmt.Errorf("%w: %w", ErrImageInvalid, err)
	}
	return cfg.Width, cfg.Height, nil
}

// --- JPEG --------------------------------------------------------------

// JPEG segments kept: APP0 (JFIF), APP2 (ICC color profile), APP14 (Adobe
// color transform). APP1 (EXIF, XMP), APP13 (IPTC), the other APPn and COM
// go. The EXIF orientation is kept, in a minimal EXIF segment of its own, so
// a photo is not shown rotated.
func stripJPEG(data []byte) ([]byte, error) {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil, ErrImageInvalid
	}
	out := bytes.NewBuffer(make([]byte, 0, len(data)))
	out.Write(data[:2])
	orientation := 0
	i := 2
	for {
		if i+4 > len(data) || data[i] != 0xFF {
			return nil, ErrImageInvalid
		}
		marker := data[i+1]
		if marker == 0xFF { // fill byte
			i++
			continue
		}
		if marker == 0xD9 { // EOI before SOS
			out.Write(data[i:])
			return out.Bytes(), nil
		}
		segLen := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if segLen < 2 || i+2+segLen > len(data) {
			return nil, ErrImageInvalid
		}
		seg := data[i : i+2+segLen]
		switch {
		case marker == 0xDA: // SOS: entropy-coded data follows, copied as is
			if orientation > 1 {
				out.Write(exifOrientationSegment(orientation))
			}
			out.Write(data[i:])
			return out.Bytes(), nil
		case marker == 0xE1:
			if o := exifOrientation(seg[4:]); o > 0 {
				orientation = o
			}
		case marker == 0xE0 || marker == 0xE2 || marker == 0xEE:
			out.Write(seg)
		case marker >= 0xE3 && marker <= 0xEF, marker == 0xFE:
			// other APPn, COM: dropped
		default:
			out.Write(seg)
		}
		i += 2 + segLen
	}
}

// exifOrientation reads tag 0x0112 from an APP1 EXIF payload, 0 if absent.
func exifOrientation(p []byte) int {
	if len(p) < 14 || !bytes.Equal(p[:6], []byte("Exif\x00\x00")) {
		return 0
	}
	tiff := p[6:]
	var bo binary.ByteOrder
	switch string(tiff[:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return 0
	}
	off := int(bo.Uint32(tiff[4:8]))
	if off < 8 || off+2 > len(tiff) {
		return 0
	}
	n := int(bo.Uint16(tiff[off : off+2]))
	for k := 0; k < n; k++ {
		e := off + 2 + k*12
		if e+12 > len(tiff) {
			return 0
		}
		if bo.Uint16(tiff[e:e+2]) == 0x0112 && bo.Uint16(tiff[e+2:e+4]) == 3 {
			v := int(bo.Uint16(tiff[e+8 : e+10]))
			if v >= 1 && v <= 8 {
				return v
			}
			return 0
		}
	}
	return 0
}

// exifOrientationSegment is an APP1 segment whose EXIF holds only the
// orientation tag.
func exifOrientationSegment(o int) []byte {
	var b bytes.Buffer
	payload := []byte("Exif\x00\x00")
	tiff := []byte{'M', 'M', 0, 42, 0, 0, 0, 8, 0, 1, // header, IFD0 at 8, one entry
		0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, byte(o), 0, 0, // orientation SHORT = o
		0, 0, 0, 0} // no next IFD
	payload = append(payload, tiff...)
	b.Write([]byte{0xFF, 0xE1})
	_ = binary.Write(&b, binary.BigEndian, uint16(len(payload)+2)) //nolint:gosec // fixed 34-byte payload
	b.Write(payload)
	return b.Bytes()
}

// --- PNG ---------------------------------------------------------------

// PNG chunks kept: the critical ones and those that change how the pixels
// look (transparency, gamma, chromaticity, sRGB, ICC profile, significant
// bits, background, physical size) or animate them. Text (tEXt, zTXt, iTXt),
// eXIf, tIME and unknown ancillary chunks go.
var pngKeep = map[string]bool{
	"IHDR": true, "PLTE": true, "IDAT": true, "IEND": true,
	"tRNS": true, "gAMA": true, "cHRM": true, "sRGB": true, "iCCP": true,
	"sBIT": true, "bKGD": true, "pHYs": true, "hIST": true, "sPLT": true,
	"acTL": true, "fcTL": true, "fdAT": true, "cICP": true, "mDCv": true, "cLLi": true,
}

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

func stripPNG(data []byte) ([]byte, error) {
	if !bytes.HasPrefix(data, pngSignature) {
		return nil, ErrImageInvalid
	}
	out := bytes.NewBuffer(make([]byte, 0, len(data)))
	out.Write(pngSignature)
	i := len(pngSignature)
	for i < len(data) {
		if i+12 > len(data) {
			return nil, ErrImageInvalid
		}
		n := int(binary.BigEndian.Uint32(data[i : i+4]))
		if n < 0 || i+12+n > len(data) {
			return nil, ErrImageInvalid
		}
		typ := string(data[i+4 : i+8])
		if pngKeep[typ] {
			out.Write(data[i : i+12+n])
		}
		i += 12 + n
		if typ == "IEND" {
			return out.Bytes(), nil
		}
	}
	return nil, ErrImageInvalid
}

// --- GIF ---------------------------------------------------------------

// GIF blocks kept: images, graphic control and the looping extension
// (NETSCAPE2.0 / ANIMEXTS1.0). Comments, plain text and other application
// extensions (XMP) go.
func stripGIF(data []byte) ([]byte, error) {
	if len(data) < 13 || (!bytes.HasPrefix(data, []byte("GIF87a")) && !bytes.HasPrefix(data, []byte("GIF89a"))) {
		return nil, ErrImageInvalid
	}
	i := 13
	if data[10]&0x80 != 0 {
		i += 3 << (int(data[10]&0x07) + 1)
	}
	if i > len(data) {
		return nil, ErrImageInvalid
	}
	out := bytes.NewBuffer(make([]byte, 0, len(data)))
	out.Write(data[:i])
	for i < len(data) {
		switch data[i] {
		case 0x3B: // trailer
			out.WriteByte(0x3B)
			return out.Bytes(), nil
		case 0x2C: // image descriptor
			start := i
			if i+10 > len(data) {
				return nil, ErrImageInvalid
			}
			fw, fh := binary.LittleEndian.Uint16(data[i+5:i+7]), binary.LittleEndian.Uint16(data[i+7:i+9])
			if int64(fw)*int64(fh) > MaxImagePixels {
				return nil, fmt.Errorf("%w: a frame is %dx%d", ErrImageTooLarge, fw, fh)
			}
			flags := data[i+9]
			i += 10
			if flags&0x80 != 0 {
				i += 3 << (int(flags&0x07) + 1)
			}
			i++ // LZW minimum code size
			end, err := gifSkipSubBlocks(data, i)
			if err != nil {
				return nil, err
			}
			out.Write(data[start:end])
			i = end
		case 0x21: // extension
			if i+2 > len(data) {
				return nil, ErrImageInvalid
			}
			label := data[i+1]
			end, err := gifSkipSubBlocks(data, i+2)
			if err != nil {
				return nil, err
			}
			keep := label == 0xF9 // graphic control
			if label == 0xFF && i+3 < len(data) && data[i+2] == 11 && i+14 <= len(data) {
				id := string(data[i+3 : i+14])
				keep = id == "NETSCAPE2.0" || id == "ANIMEXTS1.0"
			}
			if keep {
				out.Write(data[i:end])
			}
			i = end
		default:
			return nil, ErrImageInvalid
		}
	}
	return nil, ErrImageInvalid
}

// gifSkipSubBlocks returns the index after the data sub-blocks starting at i.
func gifSkipSubBlocks(data []byte, i int) (int, error) {
	for {
		if i >= len(data) {
			return 0, ErrImageInvalid
		}
		n := int(data[i])
		i++
		if n == 0 {
			return i, nil
		}
		i += n
	}
}

// --- WebP --------------------------------------------------------------

// WebP chunks: EXIF and XMP go (and their VP8X flags are cleared); image,
// alpha, animation and ICC chunks stay.
func stripWebP(data []byte) ([]byte, error) {
	if len(data) < 12 || string(data[:4]) != "RIFF" || string(data[8:12]) != "WEBP" {
		return nil, ErrImageInvalid
	}
	body := bytes.NewBuffer(make([]byte, 0, len(data)))
	body.WriteString("WEBP")
	i := 12
	for i < len(data) {
		if i+8 > len(data) {
			return nil, ErrImageInvalid
		}
		fourcc := string(data[i : i+4])
		n := int(binary.LittleEndian.Uint32(data[i+4 : i+8]))
		padded := n + n&1
		if n < 0 || i+8+n > len(data) {
			return nil, ErrImageInvalid
		}
		end := i + 8 + padded
		if end > len(data) {
			end = len(data)
		}
		switch fourcc {
		case "EXIF", "XMP ":
		case "VP8X":
			chunk := append([]byte(nil), data[i:end]...)
			if len(chunk) > 8 {
				chunk[8] &^= 0x08 | 0x04 // EXIF and XMP flags
			}
			body.Write(chunk)
		default:
			body.Write(data[i:end])
		}
		i = end
	}
	out := bytes.NewBuffer(make([]byte, 0, body.Len()+8))
	out.WriteString("RIFF")
	_ = binary.Write(out, binary.LittleEndian, uint32(body.Len())) //nolint:gosec // bounded by the upload size limit
	out.Write(body.Bytes())
	return out.Bytes(), nil
}

// webpDimensions reads the canvas size of a WebP file (VP8X, VP8L or VP8).
func webpDimensions(data []byte) (int, int, error) {
	if len(data) < 30 || string(data[:4]) != "RIFF" || string(data[8:12]) != "WEBP" {
		return 0, 0, ErrImageInvalid
	}
	c := data[12:]
	switch string(c[:4]) {
	case "VP8X":
		w := 1 + (int(c[12]) | int(c[13])<<8 | int(c[14])<<16)
		h := 1 + (int(c[15]) | int(c[16])<<8 | int(c[17])<<16)
		return w, h, nil
	case "VP8L":
		if c[8] != 0x2F {
			return 0, 0, ErrImageInvalid
		}
		b := binary.LittleEndian.Uint32(c[9:13])
		return int(b&0x3FFF) + 1, int((b>>14)&0x3FFF) + 1, nil
	case "VP8 ":
		if c[11] != 0x9D || c[12] != 0x01 || c[13] != 0x2A {
			return 0, 0, ErrImageInvalid
		}
		return int(binary.LittleEndian.Uint16(c[14:16]) & 0x3FFF), int(binary.LittleEndian.Uint16(c[16:18]) & 0x3FFF), nil
	}
	return 0, 0, ErrImageInvalid
}
