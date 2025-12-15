package generator

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
)

type EncodingEngine struct{}

func NewEncodingEngine() *EncodingEngine {
	return &EncodingEngine{}
}

func (ee *EncodingEngine) Encode(payload string, method string) string {
	switch method {
	case "url":
		return url.QueryEscape(payload)
	case "double_url":
		return url.QueryEscape(url.QueryEscape(payload))
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(payload))
	case "hex":
		return hex.EncodeToString([]byte(payload))
	case "unicode":
		return ee.unicodeEncode(payload)
	case "json_wrap":
		return fmt.Sprintf(`{"id":"%s"}`, payload)
	case "array":
		return fmt.Sprintf(`["%s"]`, payload)
	default:
		return payload
	}
}

func (ee *EncodingEngine) unicodeEncode(s string) string {
	result := ""
	for _, r := range s {
		result += fmt.Sprintf("\\u%04x", r)
	}
	return result
}
