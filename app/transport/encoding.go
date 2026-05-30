package transport

import "encoding/base64"

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeBase64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
