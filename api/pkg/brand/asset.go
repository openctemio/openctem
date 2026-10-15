package brand

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg" // registers the decoder used to check a JPEG's size
	_ "image/png"  // registers the decoder used to check a PNG's size
	"io"
	"net/http"
	"os"
)

// Limits on an operator's image. A brand image is small; anything larger
// is a mistake or an attempt to make every page load expensive.
const (
	MaxAssetBytes = 512 << 10
	maxDimension  = 4096
)

// Content types a brand image may have.
const (
	TypeSVG  = "image/svg+xml"
	TypePNG  = "image/png"
	TypeJPEG = "image/jpeg"
	TypeWebP = "image/webp"
	TypeICO  = "image/x-icon"
)

// Asset is one validated image, ready to serve.
type Asset struct {
	Data        []byte
	ContentType string
	// ETag is a strong validator of the bytes (also the cache-busting
	// version the public brand carries in the image URL).
	ETag string
}

// ErrAssetTooLarge is returned for an image over MaxAssetBytes.
var ErrAssetTooLarge = fmt.Errorf("brand image is larger than %d KiB", MaxAssetBytes>>10)

// LoadAssetFile reads and validates an image file.
func LoadAssetFile(path string) (Asset, error) {
	f, err := os.Open(path) // #nosec G304 -- an operator-configured path
	if err != nil {
		return Asset{}, fmt.Errorf("brand image %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxAssetBytes+1))
	if err != nil {
		return Asset{}, fmt.Errorf("brand image %s: %w", path, err)
	}
	a, err := NewAsset(data)
	if err != nil {
		return Asset{}, fmt.Errorf("brand image %s: %w", path, err)
	}
	return a, nil
}

// NewAsset validates image bytes: the size limit, a type from the allow
// list identified by its content (never by a file name), a decodable
// raster of bounded dimensions, and an SVG reduced to drawing elements.
func NewAsset(data []byte) (Asset, error) {
	if len(data) == 0 {
		return Asset{}, errors.New("brand image is empty")
	}
	if len(data) > MaxAssetBytes {
		return Asset{}, ErrAssetTooLarge
	}
	ct := http.DetectContentType(data)
	switch ct {
	case TypePNG, TypeJPEG:
		cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return Asset{}, fmt.Errorf("brand image is not a valid %s: %w", ct, err)
		}
		if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxDimension || cfg.Height > maxDimension {
			return Asset{}, fmt.Errorf("brand image is %dx%d; at most %dx%d", cfg.Width, cfg.Height, maxDimension, maxDimension)
		}
	case TypeWebP, TypeICO:
		// Checked by signature only; browsers decode them as images.
	default:
		clean, err := SanitizeSVG(data)
		if err != nil {
			return Asset{}, fmt.Errorf("brand image is not PNG, JPEG, WebP, ICO or a safe SVG: %w", err)
		}
		data, ct = clean, TypeSVG
	}
	sum := sha256.Sum256(data)
	return Asset{Data: data, ContentType: ct, ETag: hex.EncodeToString(sum[:8])}, nil
}
