package kex

import (
	"crypto/sha256"
	"hash"
)

// sha256New is a value pointer to the hash constructor so that
// hkdf.New can pick it up without each call importing crypto/sha256.
func sha256New() hash.Hash { return sha256.New() }
