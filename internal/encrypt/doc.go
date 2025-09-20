// Package encrypt provides a secure, flexible encryption system for handling both file and line-based encryption
// operations. Randomized mode uses AES-CTR protected with an HMAC-SHA256 tag derived via HKDF, while deterministic
// mode relies on AES-SIV. It supports parallel processing for line-mode operations and maintains compatibility
// with text-based workflows through automatic base64 encoding.
package encrypt
