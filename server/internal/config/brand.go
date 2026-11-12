package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/pkg/brand"
)

// brandFile is the optional BRAND_FILE (YAML). Image paths in it are
// relative to the file's directory. A BRAND_* variable wins over the file.
type brandFile struct {
	Name         string `yaml:"name"`
	ShortName    string `yaml:"short_name"`
	PrimaryColor string `yaml:"primary_color"`
	DocsURL      string `yaml:"docs_url"`
	WebsiteURL   string `yaml:"website_url"`
	SupportURL   string `yaml:"support_url"`
	SupportEmail string `yaml:"support_email"`
	TermsURL     string `yaml:"terms_url"`
	PrivacyURL   string `yaml:"privacy_url"`
	EmailFooter  string `yaml:"email_footer"`
	PoweredBy    *bool  `yaml:"powered_by"`
	LogoLight    string `yaml:"logo_light_file"`
	LogoDark     string `yaml:"logo_dark_file"`
	Favicon      string `yaml:"favicon_file"`
}

// maxBrandFileBytes bounds the YAML file (images are separate files).
const maxBrandFileBytes = 64 << 10

// loadBrand builds the instance brand: the defaults, then BRAND_FILE, then
// the BRAND_* variables. Any invalid value or image fails startup.
func loadBrand() (brand.Brand, error) {
	b := brand.Default()
	var f brandFile
	baseDir := ""
	if path := getEnv("BRAND_FILE", ""); path != "" {
		raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
		if err != nil {
			return b, fmt.Errorf("BRAND_FILE: %w", err)
		}
		if len(raw) > maxBrandFileBytes {
			return b, fmt.Errorf("BRAND_FILE: larger than %d KiB", maxBrandFileBytes>>10)
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(&f); err != nil {
			return b, fmt.Errorf("BRAND_FILE %s: %w", path, err)
		}
		baseDir = filepath.Dir(path)
	}
	// pick applies the file value, then the variable's (a BRAND_* variable
	// wins over the file).
	pick := func(dst *string, env, file string) {
		if file != "" {
			*dst = file
		}
		if env != "" {
			*dst = env
		}
	}
	pick(&b.Name, getEnv("BRAND_NAME", ""), f.Name)
	// The short name follows the name unless set.
	b.ShortName = ""
	pick(&b.ShortName, getEnv("BRAND_SHORT_NAME", ""), f.ShortName)
	pick(&b.PrimaryColor, getEnv("BRAND_PRIMARY_COLOR", ""), f.PrimaryColor)
	pick(&b.DocsURL, getEnv("BRAND_DOCS_URL", ""), f.DocsURL)
	pick(&b.WebsiteURL, getEnv("BRAND_WEBSITE_URL", ""), f.WebsiteURL)
	pick(&b.SupportURL, getEnv("BRAND_SUPPORT_URL", ""), f.SupportURL)
	pick(&b.SupportEmail, getEnv("BRAND_SUPPORT_EMAIL", ""), f.SupportEmail)
	pick(&b.TermsURL, getEnv("BRAND_TERMS_URL", ""), f.TermsURL)
	pick(&b.PrivacyURL, getEnv("BRAND_PRIVACY_URL", ""), f.PrivacyURL)
	pick(&b.EmailFooter, getEnv("BRAND_EMAIL_FOOTER", ""), f.EmailFooter)
	if f.PoweredBy != nil {
		b.PoweredBy = *f.PoweredBy
	}
	if v := getEnv("BRAND_POWERED_BY", strconv.FormatBool(b.PoweredBy)); v != "" {
		on, err := strconv.ParseBool(v)
		if err != nil {
			return b, fmt.Errorf("BRAND_POWERED_BY: %q is not true or false", v)
		}
		b.PoweredBy = on
	}
	if err := b.Validate(); err != nil {
		return b, fmt.Errorf("brand: %w", err)
	}

	images := []struct {
		kind            brand.AssetKind
		name, env, file string
	}{
		{brand.AssetLogoLight, "BRAND_LOGO_LIGHT_FILE", getEnv("BRAND_LOGO_LIGHT_FILE", ""), f.LogoLight},
		{brand.AssetLogoDark, "BRAND_LOGO_DARK_FILE", getEnv("BRAND_LOGO_DARK_FILE", ""), f.LogoDark},
		{brand.AssetFavicon, "BRAND_FAVICON_FILE", getEnv("BRAND_FAVICON_FILE", ""), f.Favicon},
	}
	for _, img := range images {
		path := img.env
		if path == "" && img.file != "" {
			path = img.file
			if !filepath.IsAbs(path) {
				path = filepath.Join(baseDir, path)
			}
		}
		if path == "" {
			continue
		}
		a, err := brand.LoadAssetFile(path)
		if err != nil {
			return b, fmt.Errorf("%s: %w", img.name, err)
		}
		if b.Assets == nil {
			b.Assets = map[brand.AssetKind]brand.Asset{}
		}
		b.Assets[img.kind] = a
	}
	return b, nil
}
