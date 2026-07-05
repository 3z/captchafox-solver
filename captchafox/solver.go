package captchafox

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"math"
	"math/rand"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const (
	slideTrackWidthCSS  = 300
	slidePieceSizeCSS   = 50
	slideTrackHeightCSS = 60
)

// CaptchaFoxSolver runs the full CaptchaFox flow without a browser: it replays
// a real-Chrome attestation object as `cs` and solves the slide challenge by
// detecting the puzzle gap in the background image.
type CaptchaFoxSolver struct {
	client        *CaptchaFoxClient
	siteKey       string
	site          string
	challengeType string
	lang          string
	profile       *AttestationProfile
}

// NewCaptchaFoxSolver constructs a solver. A nil client is replaced with a
// default CaptchaFoxClient.
func NewCaptchaFoxSolver(client *CaptchaFoxClient, siteKey, site, challengeType, lang string, profile *AttestationProfile) *CaptchaFoxSolver {
	if client == nil {
		client = NewCaptchaFoxClient()
	}
	if site == "" {
		site = DefaultSite
	}
	if challengeType == "" {
		challengeType = "slide"
	}
	if lang == "" {
		lang = "en"
	}
	return &CaptchaFoxSolver{
		client:        client,
		siteKey:       siteKey,
		site:          site,
		challengeType: challengeType,
		lang:          lang,
		profile:       profile,
	}
}

// newProfile reuses a fixed profile when set, otherwise mints a fresh random
// per-user fingerprint for each solve.
func (s *CaptchaFoxSolver) newProfile() *AttestationProfile {
	if s.profile != nil {
		return s.profile
	}
	return RandomAttestationProfile()
}

// Probe fetches the config and issues a challenge with a synthesized
// attestation. A non-error response means the attestation (cs) was accepted by
// the live server.
func (s *CaptchaFoxSolver) Probe() (map[string]interface{}, error) {
	config, err := s.client.FetchConfig(s.siteKey, s.site)
	if err != nil {
		return nil, err
	}
	cs := BuildAttestation(s.site, s.newProfile())
	k := s.solvePowFromInput(config.Raw["m"])
	return s.client.Challenge(config, s.challengeType, cs, k, s.lang)
}

// Solve runs the full flow with up to maxAttempts retries and returns a
// verified response token.
func (s *CaptchaFoxSolver) Solve(maxAttempts int) (string, error) {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		token, err := s.solveOnce()
		if err == nil {
			return token, nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("solve failed after %d attempt(s): %w", maxAttempts, lastErr)
}

// solveOnce performs a single end-to-end solve attempt.
func (s *CaptchaFoxSolver) solveOnce() (string, error) {
	config, err := s.client.FetchConfig(s.siteKey, s.site)
	if err != nil {
		return "", err
	}
	cs := BuildAttestation(s.site, s.newProfile())
	h := config.H()
	k := s.solvePowFromInput(config.Raw["m"])

	challenge, err := s.client.Challenge(config, s.challengeType, cs, k, s.lang)
	if err != nil {
		return "", err
	}
	// Some site keys return a token immediately (e.g. the public test key).
	if token, ok := challenge["token"].(string); ok && token != "" {
		return token, nil
	}
	if ch, ok := challenge["h"].(string); ok && ch != "" {
		h = ch
	}
	if j := challenge["j"]; j != nil {
		k = s.solvePowFromInput(j)
	}

	challengeData, _ := challenge["challenge"].(map[string]interface{})
	mv, elapsed, position, err := s.solveSlide(challengeData)
	if err != nil {
		return "", err
	}

	verifyPayload := map[string]interface{}{
		"sk":   s.siteKey,
		"mv":   mv,
		"t":    elapsed,
		"p":    position,
		"h":    h,
		"cs":   cs,
		"k":    k,
		"type": s.challengeType,
		"host": hostname(s.site),
	}
	result, err := s.client.Verify(verifyPayload, s.site)
	if err != nil {
		return "", err
	}
	token, ok := result["token"].(string)
	if !ok || token == "" {
		return "", fmt.Errorf("verify did not return a token: %v", result)
	}
	return token, nil
}

// solvePowFromInput parses the worker PoW message. config.m / challenge.j is
// [tag, seed, difficultyBinaryString]; the tag (index 0) is ignored, index 1 is
// the seed, index 2 is the difficulty parsed from a binary string (e.g. "101"
// -> 5 leading hex zeros). Returns 0 when the input is not a 3-element array.
func (s *CaptchaFoxSolver) solvePowFromInput(input interface{}) int {
	arr, ok := input.([]interface{})
	if !ok || len(arr) != 3 {
		return 0
	}
	seed := ifaceToString(arr[1])
	diffStr := ifaceToString(arr[2])
	difficulty, err := strconv.ParseInt(diffStr, 2, 64)
	if err != nil {
		return 0
	}
	return SolvePow(seed, int(difficulty))
}

// solveSlide detects the gap in the background image and synthesizes a trail.
func (s *CaptchaFoxSolver) solveSlide(challenge map[string]interface{}) ([]float64, float64, float64, error) {
	bgURL, _ := challenge["bg"].(string)
	if bgURL == "" {
		return nil, 0, 0, fmt.Errorf("slide challenge missing bg image: %v", challenge)
	}
	gapX, err := s.detectGapX(bgURL)
	if err != nil {
		return nil, 0, 0, err
	}
	position := gapX
	maxPos := float64(slideTrackWidthCSS - slidePieceSizeCSS)
	if position < 0 {
		position = 0
	} else if position > maxPos {
		position = maxPos
	}
	mv, elapsed := s.synthesizeTrail(position)
	return mv, elapsed, position, nil
}

// detectGapX detects the slide target (gap) left-edge x in CSS pixels (0..300).
//
// It decodes the PNG background, converts each pixel to 8-bit RGB, computes the
// per-column mean deviation of each pixel from the global median background
// color, then finds the contiguous run of columns above (mean + 1.5*std) with
// the largest total deviation. Its left edge is mapped from image pixels to
// the 300px CSS track width.
func (s *CaptchaFoxSolver) detectGapX(bgURL string) (float64, error) {
	raw, err := s.fetchBgBytes(bgURL)
	if err != nil {
		return 0, err
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return 0, fmt.Errorf("decode bg png: %w", err)
	}
	bounds := img.Bounds()
	w := bounds.Dx()
	h := bounds.Dy()
	if w == 0 || h == 0 {
		return 0, fmt.Errorf("empty bg image")
	}

	// Build the RGB grid: r[y][x] = {R, G, B} in 0..255.
	r := make([][][3]int, h)
	for y := 0; y < h; y++ {
		row := make([][3]int, w)
		for x := 0; x < w; x++ {
			cr, cg, cb, _ := img.At(bounds.Min.X+x, bounds.Min.Y+y).RGBA()
			row[x] = [3]int{int(cr >> 8), int(cg >> 8), int(cb >> 8)}
		}
		r[y] = row
	}

	// Per-column median color (median over rows, per channel).
	colMedian := make([][3]float64, w)
	for x := 0; x < w; x++ {
		for c := 0; c < 3; c++ {
			vals := make([]float64, h)
			for y := 0; y < h; y++ {
				vals[y] = float64(r[y][x][c])
			}
			colMedian[x][c] = medianFloat(vals)
		}
	}

	// Global background reference: median of the per-column medians, so a large
	// foreground object does not skew the reference.
	var bgColor [3]float64
	for c := 0; c < 3; c++ {
		vals := make([]float64, w)
		for x := 0; x < w; x++ {
			vals[x] = colMedian[x][c]
		}
		bgColor[c] = medianFloat(vals)
	}

	// Per-column mean deviation from the background color (mean over rows and
	// channels).
	coldist := make([]float64, w)
	for x := 0; x < w; x++ {
		var sum float64
		for y := 0; y < h; y++ {
			for c := 0; c < 3; c++ {
				sum += math.Abs(float64(r[y][x][c]) - bgColor[c])
			}
		}
		coldist[x] = sum / float64(h*3)
	}

	// Threshold = mean + 1.5*std (population standard deviation).
	var meanVal float64
	for _, v := range coldist {
		meanVal += v
	}
	meanVal /= float64(w)
	var varSum float64
	for _, v := range coldist {
		d := v - meanVal
		varSum += d * d
	}
	stdVal := math.Sqrt(varSum / float64(w))
	threshold := meanVal + 1.5*stdVal

	searchStart := int(float64(w) * 0.15)

	// Default to the global argmax in case no run clears the threshold.
	bestLeft := 0
	bestVal := math.Inf(-1)
	for x, v := range coldist {
		if v > bestVal {
			bestVal = v
			bestLeft = x
		}
	}

	// Find contiguous runs above threshold; pick the one with the largest
	// total deviation.
	bestScore := 0.0
	for i := searchStart; i < w; {
		if coldist[i] <= threshold {
			i++
			continue
		}
		j := i
		for j < w && coldist[j] > threshold {
			j++
		}
		score := 0.0
		for x := i; x < j; x++ {
			score += coldist[x]
		}
		if score > bestScore {
			bestScore = score
			bestLeft = i
		}
		i = j
	}

	return float64(bestLeft) / float64(w) * slideTrackWidthCSS, nil
}

// synthesizeTrail synthesizes a human-like slide trail. Returns (mv, elapsed)
// where mv is a flat list [dy0, dx0, dy1, dx1, ...] of cumulative offsets (max
// 80 numbers / 40 samples) whose final dx equals solution, and elapsed is the
// drag time in seconds (2dp). The horizontal motion follows an ease-in-out
// cosine curve with small vertical jitter.
func (s *CaptchaFoxSolver) synthesizeTrail(solution float64) ([]float64, float64) {
	const (
		samples  = 34
		duration = 1.35
	)
	mv := make([]float64, 0, samples*2)
	lastX := 0.0
	for i := 1; i <= samples; i++ {
		progress := float64(i) / float64(samples)
		eased := 0.5 * (1 - math.Cos(math.Pi*progress))
		x := roundTo(solution*eased, 2)
		dy := roundTo(rand.Float64()*2.4-1.2, 2) // uniform(-1.2, 1.2)
		mv = append(mv, dy, x)
		lastX = x
	}
	if len(mv) > 80 {
		mv = mv[:80]
	}
	if len(mv) > 0 {
		mv[len(mv)-1] = roundTo(lastX, 2)
	}
	return mv, roundTo(duration, 2)
}

// fetchBgBytes fetches the background image bytes, supporting data URLs and
// plain HTTP(S) URLs.
func (s *CaptchaFoxSolver) fetchBgBytes(bgURL string) ([]byte, error) {
	if strings.HasPrefix(bgURL, "data:") {
		idx := strings.Index(bgURL, ",")
		if idx < 0 {
			return nil, fmt.Errorf("invalid bg data URL")
		}
		raw, err := base64.StdEncoding.DecodeString(bgURL[idx+1:])
		if err != nil {
			return nil, fmt.Errorf("decode bg base64: %w", err)
		}
		return raw, nil
	}
	req, err := http.NewRequest(http.MethodGet, bgURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.client.ua())
	resp, err := s.client.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("fetch bg failed: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// medianFloat returns the median of vals (averaging the two middle values for
// an even count), matching numpy.median semantics.
func medianFloat(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	sort.Float64s(sorted)
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// roundTo rounds x to `digits` decimal places (round half away from zero).
func roundTo(x float64, digits int) float64 {
	pow := math.Pow(10, float64(digits))
	return math.Round(x*pow) / pow
}

// ifaceToString converts a decoded JSON value to its string form, handling
// json.Number (from UseNumber decoding) and float64 without spurious trailing
// decimals, mirroring Python's str() for PoW seed/difficulty fields.
func ifaceToString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}
