package captchafox

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"math/rand"
	"time"
)

//go:embed attestation_template.json
var attestationTemplateJSON []byte

// AttestationProfile is a self-consistent per-user Chrome attestation profile.
// Only genuine per-user signals are varied (screen, GPU, timezone, core count,
// languages, dark mode). The UA, platform and property inventories stay
// constant from the captured Chrome template so the fingerprint remains
// Chrome-plausible and consistent with the HTTP User-Agent header.
type AttestationProfile struct {
	DarkMode            bool
	HardwareConcurrency int
	TimezoneOffset      int
	Languages           []string
	WebGLVendor         string
	WebGLRenderer       string
	ScreenWidth         int
	ScreenHeight        int
	PixelRatio          int
}

var profileScreenPool = [][3]int{
	{1920, 1080, 1}, {2560, 1440, 1}, {1366, 768, 1}, {3840, 2160, 1},
	{1920, 1200, 1}, {1680, 1050, 1}, {1280, 800, 2}, {1440, 900, 1},
	{1600, 900, 1}, {2880, 1800, 2},
}

var profileWebGLPool = [][2]string{
	{"Google Inc. (Google)", "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)"},
	{"Google Inc. (Google)", "ANGLE (Google, Vulkan 1.3.0 (Intel(R) UHD Graphics 630 (0x00003E9B)), Intel-open-source Mesa)"},
	{"Google Inc. (Google)", "ANGLE (Google, Vulkan 1.3.0 (Intel(R) Iris(R) Xe Graphics (0x00009A49)), Intel-open-source Mesa)"},
	{"Google Inc. (Google)", "ANGLE (Google, Vulkan 1.3.0 (NVIDIA GeForce GTX 1660), NVIDIA proprietary driver)"},
	{"Google Inc. (Google)", "ANGLE (Google, Vulkan 1.3.0 (AMD Radeon RX 580 (0x000067DF)), AMD open-source Mesa)"},
}

var profileTimezonePool = []int{0, -480, -300, 240, 300, 480, -60, 360, 420, 600, -330}

var profileCoresPool = []int{4, 8, 12, 16, 32}

var profileLanguagesPool = [][]string{
	{"en-US"},
	{"en-US", "en"},
	{"en-GB"},
	{"de-DE", "de", "en"},
	{"fr-FR", "fr", "en"},
	{"en-US", "en", "es"},
	{"pt-BR", "pt", "en"},
}

// RandomAttestationProfile mints a fresh randomized per-user fingerprint by
// sampling from the variation pools. The global math/rand source is
// auto-seeded (Go 1.20+) and concurrency-safe.
func RandomAttestationProfile() *AttestationProfile {
	screen := profileScreenPool[rand.Intn(len(profileScreenPool))]
	webgl := profileWebGLPool[rand.Intn(len(profileWebGLPool))]
	langsSrc := profileLanguagesPool[rand.Intn(len(profileLanguagesPool))]
	langs := make([]string, len(langsSrc))
	copy(langs, langsSrc)

	return &AttestationProfile{
		DarkMode:            rand.Intn(2) == 1,
		HardwareConcurrency: profileCoresPool[rand.Intn(len(profileCoresPool))],
		TimezoneOffset:      profileTimezonePool[rand.Intn(len(profileTimezonePool))],
		Languages:           langs,
		WebGLVendor:         webgl[0],
		WebGLRenderer:       webgl[1],
		ScreenWidth:         screen[0],
		ScreenHeight:        screen[1],
		PixelRatio:          screen[2],
	}
}

// screenPayload builds the CF0120 screen descriptor.
func (p *AttestationProfile) screenPayload() map[string]interface{} {
	return map[string]interface{}{
		"width":    p.ScreenWidth,
		"height":   p.ScreenHeight,
		"availW":   p.ScreenWidth,
		"availH":   p.ScreenHeight,
		"clrDepth": 24,
		"pxDepth":  24,
		"pxRatio":  p.PixelRatio,
		"outerW":   p.ScreenWidth,
		"outerH":   p.ScreenHeight,
	}
}

// webglPayload builds the CF0114 WebGL parameter list.
func (p *AttestationProfile) webglPayload() []interface{} {
	return []interface{}{
		p.WebGLVendor,
		p.WebGLRenderer,
		"WebKit",
		"WebKit WebGL",
		"WebGL 1.0 (OpenGL ES 2.0 Chromium)",
	}
}

// BuildAttestation deep-copies the captured Chrome attestation template and
// freshens it for a solve: CF0106 (timestamp) and CF0148 (site) are always
// refreshed. When a profile is supplied the per-user signal fields
// (CF0101, CF0105, CF0108, CF0111, CF0114, CF0120, CF0121) are overridden so
// each call yields a distinct fingerprint while remaining Chrome-consistent.
func BuildAttestation(site string, profile *AttestationProfile) map[string]interface{} {
	cs := deepCopyTemplate()
	cs["CF0106"] = time.Now().UnixMilli()
	cs["CF0148"] = site
	if profile != nil {
		cs["CF0101"] = profile.DarkMode
		cs["CF0105"] = profile.HardwareConcurrency
		cs["CF0108"] = profile.TimezoneOffset
		cs["CF0111"] = profile.Languages
		cs["CF0114"] = profile.webglPayload()
		cs["CF0120"] = profile.screenPayload()
		cs["CF0121"] = []interface{}{profile.WebGLVendor, profile.WebGLRenderer}
	}
	return cs
}

// deepCopyTemplate unmarshals the embedded template into a fresh map. Using
// UseNumber preserves all numeric values exactly (no float64 coercion) so the
// re-marshalled attestation is byte-faithful to the captured Chrome template.
func deepCopyTemplate() map[string]interface{} {
	dec := json.NewDecoder(bytes.NewReader(attestationTemplateJSON))
	dec.UseNumber()
	var cs map[string]interface{}
	if err := dec.Decode(&cs); err != nil {
		panic("captchafox: failed to decode embedded attestation template: " + err.Error())
	}
	return cs
}
