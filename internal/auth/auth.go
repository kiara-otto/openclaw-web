package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// HashPassword creates a SHA256 hash of the password
func HashPassword(p string) string {
	h := sha256.Sum256([]byte(p))
	return base64.StdEncoding.EncodeToString(h[:])
}

// VerifyPassword compares a password hash with a plain password
func VerifyPassword(password, hash string) bool {
	return HashPassword(password) == hash
}

// RandomID generates a random ID
func RandomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}
