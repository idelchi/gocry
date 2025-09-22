package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// encryptBytes encrypts the given byte slice using AES-CTR with an HMAC tag.
// Output layout: [header | IV | ciphertext | tag].
func (e *Encryptor) encryptBytes(data []byte) ([]byte, error) {
	encKey, macKey, err := deriveRandomizedKeys(e.Key)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	header := newEnvelopeHeader(modeRandomized)
	totalLen := len(header) + aes.BlockSize + len(data) + envelopeTagSize
	out := make([]byte, totalLen)

	offset := 0
	copy(out[offset:], header)

	offset += len(header)

	initializationVector := out[offset : offset+aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, initializationVector); err != nil {
		return nil, fmt.Errorf("generating IV: %w", err)
	}

	offset += aes.BlockSize

	ciphertext := out[offset : offset+len(data)]
	stream := cipher.NewCTR(block, initializationVector)

	stream.XORKeyStream(ciphertext, data)

	offset += len(data)

	mac := hmac.New(sha256.New, macKey)
	mac.Write(out[:offset])

	tag := mac.Sum(nil)
	copy(out[offset:], tag)

	return out, nil
}

// decryptBytes decrypts data produced by encryptBytes.
func (e *Encryptor) decryptBytes(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < envelopeHeaderSize+aes.BlockSize+envelopeTagSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrProcessing)
	}

	encKey, macKey, err := deriveRandomizedKeys(e.Key)
	if err != nil {
		return nil, err
	}

	header := ciphertext[:envelopeHeaderSize]

	mode, err := parseEnvelopeHeader(header)
	if err != nil {
		return nil, err
	}

	if mode != modeRandomized {
		return nil, fmt.Errorf("%w: unexpected mode for randomized decryption", ErrProcessing)
	}

	mac := hmac.New(sha256.New, macKey)
	mac.Write(ciphertext[:len(ciphertext)-envelopeTagSize])

	tag := ciphertext[len(ciphertext)-envelopeTagSize:]
	if !hmac.Equal(mac.Sum(nil), tag) {
		return nil, fmt.Errorf("%w: authentication failed", ErrProcessing)
	}

	ivStart := envelopeHeaderSize
	ivEnd := ivStart + aes.BlockSize
	initializationVector := ciphertext[ivStart:ivEnd]

	body := ciphertext[ivEnd : len(ciphertext)-envelopeTagSize]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	plaintext := make([]byte, len(body))
	stream := cipher.NewCTR(block, initializationVector)
	stream.XORKeyStream(plaintext, body)

	return plaintext, nil
}
