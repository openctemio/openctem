package attachment

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"
)

func testImage() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 4, 3))
	for x := 0; x < 4; x++ {
		for y := 0; y < 3; y++ {
			img.Set(x, y, color.RGBA{uint8(x * 60), uint8(y * 80), 200, 255})
		}
	}
	return img
}

// exifWithGPS is an APP1 EXIF payload with an orientation (6) and a GPS IFD
// pointer, enough for a reader to find location data.
func exifWithGPS() []byte {
	tiff := []byte{'I', 'I', 42, 0, 8, 0, 0, 0, 2, 0}
	entry := func(tag, typ uint16, count, value uint32) []byte {
		b := make([]byte, 12)
		binary.LittleEndian.PutUint16(b[0:], tag)
		binary.LittleEndian.PutUint16(b[2:], typ)
		binary.LittleEndian.PutUint32(b[4:], count)
		binary.LittleEndian.PutUint32(b[8:], value)
		return b
	}
	tiff = append(tiff, entry(0x0112, 3, 1, 6)...)
	tiff = append(tiff, entry(0x8825, 4, 1, 38)...) // GPS IFD
	tiff = append(tiff, 0, 0, 0, 0)
	tiff = append(tiff, []byte("GPSLatitude-52.3676N-4.9041E")...)
	return append([]byte("Exif\x00\x00"), tiff...)
}

func jpegWithMetadata(t *testing.T) []byte {
	t.Helper()
	var plain bytes.Buffer
	if err := jpeg.Encode(&plain, testImage(), nil); err != nil {
		t.Fatal(err)
	}
	seg := func(marker byte, payload []byte) []byte {
		b := []byte{0xFF, marker, 0, 0}
		binary.BigEndian.PutUint16(b[2:], uint16(len(payload)+2))
		return append(b, payload...)
	}
	out := append([]byte{}, plain.Bytes()[:2]...)
	out = append(out, seg(0xE1, exifWithGPS())...)
	out = append(out, seg(0xE1, []byte("http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta>author=alice</x:xmpmeta>"))...)
	out = append(out, seg(0xED, []byte("Photoshop 3.0\x00IPTC-city=Amsterdam"))...)
	out = append(out, seg(0xFE, []byte("comment: taken at home"))...)
	return append(out, plain.Bytes()[2:]...)
}

func TestSanitizeImage_JPEGDropsMetadataKeepsOrientationAndPixels(t *testing.T) {
	in := jpegWithMetadata(t)
	out, err := SanitizeImage(in, "image/jpeg")
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"GPSLatitude", "xmpmeta", "IPTC-city", "taken at home"} {
		if bytes.Contains(out, []byte(leak)) {
			t.Errorf("%q survived", leak)
		}
	}
	if o := jpegOrientation(out); o != 6 {
		t.Errorf("orientation = %d, want 6 kept", o)
	}
	a, err := jpeg.Decode(bytes.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	b, err := jpeg.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("sanitized JPEG does not decode: %v", err)
	}
	if a.Bounds() != b.Bounds() || a.At(2, 1) != b.At(2, 1) {
		t.Error("pixels changed")
	}
}

func jpegOrientation(data []byte) int {
	i := 2
	for i+4 <= len(data) && data[i] == 0xFF {
		n := int(binary.BigEndian.Uint16(data[i+2:]))
		if data[i+1] == 0xE1 {
			return exifOrientation(data[i+4 : i+2+n])
		}
		if data[i+1] == 0xDA {
			return 0
		}
		i += 2 + n
	}
	return 0
}

func pngChunk(typ string, data []byte) []byte {
	b := make([]byte, 8, 12+len(data))
	binary.BigEndian.PutUint32(b, uint32(len(data)))
	copy(b[4:], typ)
	b = append(b, data...)
	crc := crc32.ChecksumIEEE(append([]byte(typ), data...))
	return binary.BigEndian.AppendUint32(b, crc)
}

func TestSanitizeImage_PNGDropsTextAndExifChunks(t *testing.T) {
	var plain bytes.Buffer
	if err := png.Encode(&plain, testImage()); err != nil {
		t.Fatal(err)
	}
	p := plain.Bytes()
	// signature + IHDR (8 + 25), then our chunks, then the rest.
	in := append([]byte{}, p[:33]...)
	in = append(in, pngChunk("tEXt", []byte("Author\x00alice@example.com"))...)
	in = append(in, pngChunk("eXIf", exifWithGPS()[6:])...)
	in = append(in, pngChunk("tIME", []byte{7, 234, 10, 12, 1, 2, 3})...)
	in = append(in, p[33:]...)
	out, err := SanitizeImage(in, "image/png")
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"alice@example.com", "GPSLatitude", "tIME"} {
		if bytes.Contains(out, []byte(leak)) {
			t.Errorf("%q survived", leak)
		}
	}
	if !bytes.Equal(out, p) {
		t.Error("sanitized PNG differs from the image without the chunks")
	}
}

func TestSanitizeImage_GIFDropsCommentsKeepsAnimation(t *testing.T) {
	pal := color.Palette{color.Black, color.White}
	frame := image.NewPaletted(image.Rect(0, 0, 2, 2), pal)
	var plain bytes.Buffer
	if err := gif.EncodeAll(&plain, &gif.GIF{Image: []*image.Paletted{frame, frame}, Delay: []int{1, 1}, LoopCount: 0}); err != nil {
		t.Fatal(err)
	}
	p := plain.Bytes()
	header := 13
	if p[10]&0x80 != 0 {
		header += 3 * (1 << (int(p[10]&7) + 1))
	}
	comment := []byte{0x21, 0xFE, 11}
	comment = append(comment, []byte("secret note")...)
	comment = append(comment, 0)
	in := append(append(append([]byte{}, p[:header]...), comment...), p[header:]...)
	out, err := SanitizeImage(in, "image/gif")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("secret note")) {
		t.Error("comment survived")
	}
	g, err := gif.DecodeAll(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("sanitized GIF does not decode: %v", err)
	}
	if len(g.Image) != 2 || g.LoopCount != 0 {
		t.Errorf("frames %d loop %d: animation lost", len(g.Image), g.LoopCount)
	}
}

// webpVP8L is a 1x1 lossless WebP.
var webpVP8L = []byte("RIFF\x1a\x00\x00\x00WEBPVP8L\x0d\x00\x00\x00\x2f\x00\x00\x00\x10\x07\x10\x11\x11\x88\x88\xfe\x07\x00")

func TestSanitizeImage_WebPDropsExifAndXMP(t *testing.T) {
	vp8x := []byte("VP8X\x0a\x00\x00\x00")
	vp8x = append(vp8x, 0x08|0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0) // EXIF+XMP flags, 1x1 canvas
	exif := append([]byte("EXIF"), 0, 0, 0, 0)
	payload := []byte("GPSLatitude!")
	binary.LittleEndian.PutUint32(exif[4:], uint32(len(payload)))
	exif = append(exif, payload...)
	body := append(append(append([]byte("WEBP"), vp8x...), webpVP8L[12:]...), exif...)
	in := append([]byte("RIFF\x00\x00\x00\x00"), body...)
	binary.LittleEndian.PutUint32(in[4:], uint32(len(body)))

	out, err := SanitizeImage(in, "image/webp")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("GPSLatitude")) {
		t.Error("EXIF chunk survived")
	}
	if out[20]&(0x08|0x04) != 0 {
		t.Error("VP8X still flags EXIF/XMP")
	}
	if int(binary.LittleEndian.Uint32(out[4:])) != len(out)-8 {
		t.Error("RIFF size not rewritten")
	}
	if w, h, err := webpDimensions(out); err != nil || w != 1 || h != 1 {
		t.Errorf("dims %dx%d %v", w, h, err)
	}
	if _, err := SanitizeImage(webpVP8L, "image/webp"); err != nil {
		t.Errorf("plain lossless WebP: %v", err)
	}
}

func TestSanitizeImage_RefusesDecompressionBombs(t *testing.T) {
	var plain bytes.Buffer
	if err := png.Encode(&plain, testImage()); err != nil {
		t.Fatal(err)
	}
	p := append([]byte{}, plain.Bytes()...)
	// IHDR claims 20000 x 20000 (400 MP), valid CRC.
	ihdr := append([]byte{}, p[16:29]...)
	binary.BigEndian.PutUint32(ihdr[0:], 20000)
	binary.BigEndian.PutUint32(ihdr[4:], 20000)
	copy(p[8:33], pngChunk("IHDR", ihdr))
	if _, err := SanitizeImage(p, "image/png"); !errors.Is(err, ErrImageTooLarge) {
		t.Errorf("400 MP PNG: err = %v, want ErrImageTooLarge", err)
	}
	// A WebP canvas of 16384 x 16384.
	vp8x := append([]byte("RIFF\x16\x00\x00\x00WEBPVP8X\x0a\x00\x00\x00"), 0, 0, 0, 0, 0xFF, 0x3F, 0, 0xFF, 0x3F, 0)
	if _, err := SanitizeImage(vp8x, "image/webp"); !errors.Is(err, ErrImageTooLarge) {
		t.Errorf("large WebP: err = %v, want ErrImageTooLarge", err)
	}
}

func TestSanitizeImage_RefusesMalformed(t *testing.T) {
	for ct, data := range map[string][]byte{
		"image/png":  []byte("\x89PNG\r\n\x1a\nnot really"),
		"image/jpeg": {0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF},
		"image/gif":  []byte("GIF89a"),
		"image/webp": []byte("RIFF\x04\x00\x00\x00WEBP"),
	} {
		if _, err := SanitizeImage(data, ct); !errors.Is(err, ErrImageInvalid) {
			t.Errorf("%s: err = %v, want ErrImageInvalid", ct, err)
		}
	}
}

// Truncated and corrupted inputs never panic: the parsers bound every index.
func TestSanitizeImage_TruncatedInputsDoNotPanic(t *testing.T) {
	var p, g bytes.Buffer
	_ = png.Encode(&p, testImage())
	_ = gif.Encode(&g, testImage(), nil)
	inputs := map[string][]byte{
		"image/jpeg": jpegWithMetadata(t), "image/png": p.Bytes(),
		"image/gif": g.Bytes(), "image/webp": webpVP8L,
	}
	for ct, full := range inputs {
		for n := 0; n < len(full); n++ {
			_, _ = SanitizeImage(full[:n], ct)
			flipped := append([]byte{}, full...)
			flipped[n] ^= 0xFF
			_, _ = SanitizeImage(flipped, ct)
		}
	}
}
