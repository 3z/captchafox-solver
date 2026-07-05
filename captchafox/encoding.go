package captchafox

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
)

// EncodePayload encodes the text/plain POST body used by CaptchaFox
// challenge/verify calls. The encoding pipeline mirrors the Python reference
// (encode_captchafox_payload):
//
//	1. compact JSON (no HTML escaping, like ensure_ascii=False)
//	2. gzip
//	3. prefix the magic bytes [0x01, 0x04]
//	4. XOR each compressed byte with (index+4)&0xFF
//
// The second prefix byte (0x04) doubles as the initial XOR key, so byte 0 of
// the gzip stream is XOR'd with 4, byte 1 with 5, and so on, wrapping at 256.
func EncodePayload(payload map[string]interface{}) ([]byte, error) {
	raw, err := marshalCompact(payload)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	compressed := buf.Bytes()

	out := make([]byte, 0, len(compressed)+2)
	out = append(out, 0x01, 0x04)
	for i, b := range compressed {
		out = append(out, b^byte((i+0x04)&0xFF))
	}
	return out, nil
}

// marshalCompact produces compact JSON (no extra whitespace) and disables HTML
// escaping so that characters such as '<', '>' and '&' are emitted verbatim,
// matching Python's json.dumps(..., ensure_ascii=False).
func marshalCompact(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// json.Encoder.Encode appends a trailing newline; strip it to match
	// json.dumps which does not.
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return b, nil
}
