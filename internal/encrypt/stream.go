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

const streamBufferSize = 4096

// encryptStream encrypts data from reader to writer using AES-CTR mode protected by an HMAC tag.
// The output layout is: [header | IV | ciphertext | tag].
func (e *Encryptor) encryptStream(reader io.Reader, writer io.Writer) error {
	encKey, macKey, err := deriveRandomizedKeys(e.Key)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	header := newEnvelopeHeader(modeRandomized)
	if _, err := writer.Write(header); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	mac := hmac.New(sha256.New, macKey)
	mac.Write(header)

	initializationVector := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, initializationVector); err != nil {
		return fmt.Errorf("generating IV: %w", err)
	}

	if _, err := writer.Write(initializationVector); err != nil {
		return fmt.Errorf("writing IV: %w", err)
	}

	mac.Write(initializationVector)

	stream := cipher.NewCTR(block, initializationVector)
	buf := make([]byte, streamBufferSize)
	encrypted := make([]byte, streamBufferSize)

	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			stream.XORKeyStream(encrypted[:n], buf[:n])
			mac.Write(encrypted[:n])

			if _, err := writer.Write(encrypted[:n]); err != nil {
				return fmt.Errorf("writing encrypted data: %w", err)
			}
		}

		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			return fmt.Errorf("reading data: %w", readErr)
		}
	}

	tag := mac.Sum(nil)
	if _, err := writer.Write(tag); err != nil {
		return fmt.Errorf("writing authentication tag: %w", err)
	}

	return nil
}

// decryptStream verifies and decrypts data produced by encryptStream.
//

//nolint:gocognit	// function complexity is acceptable
func (e *Encryptor) decryptStream(reader io.Reader, writer io.Writer, header []byte) error {
	encKey, macKey, err := deriveRandomizedKeys(e.Key)
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, macKey)
	mac.Write(header)

	initializationVector := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(reader, initializationVector); err != nil {
		return fmt.Errorf("reading IV: %w", err)
	}

	mac.Write(initializationVector)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	stream := cipher.NewCTR(block, initializationVector)
	buf := make([]byte, streamBufferSize)
	plainChunk := make([]byte, streamBufferSize)
	tagBuffer := make([]byte, 0, envelopeTagSize)

	for {
		n, readErr := reader.Read(buf)
		if n > 0 { //nolint:nestif // readability is acceptable
			//nolint:gocritic // Append should be to another slice
			combined := append(tagBuffer, buf[:n]...)

			if len(combined) <= envelopeTagSize {
				tagBuffer = combined
			} else {
				processLen := len(combined) - envelopeTagSize
				chunk := combined[:processLen]

				tagBuffer = append(tagBuffer[:0], combined[processLen:]...)

				mac.Write(chunk)

				if len(plainChunk) < processLen {
					plainChunk = make([]byte, processLen)
				}

				plaintext := plainChunk[:processLen]
				stream.XORKeyStream(plaintext, chunk)

				if _, err := writer.Write(plaintext); err != nil {
					return fmt.Errorf("writing decrypted data: %w", err)
				}
			}
		}

		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			return fmt.Errorf("reading encrypted data: %w", readErr)
		}
	}

	if len(tagBuffer) != envelopeTagSize {
		return fmt.Errorf("%w: authentication tag missing", ErrProcessing)
	}

	if !hmac.Equal(mac.Sum(nil), tagBuffer) {
		return fmt.Errorf("%w: authentication failed", ErrProcessing)
	}

	return nil
}

// encryptDeterministic encrypts the entire data buffer deterministically using AES-SIV.
func (e *Encryptor) encryptDeterministic(data []byte) ([]byte, error) {
	daead, err := newDAEAD(e.Key)
	if err != nil {
		return nil, err
	}

	return daead.EncryptDeterministically(data, nil) //nolint:wrapcheck // error does not need wrapping
}

// decryptDeterministic decrypts data previously encrypted with AES-SIV.
func (e *Encryptor) decryptDeterministic(data []byte) ([]byte, error) {
	daead, err := newDAEAD(e.Key)
	if err != nil {
		return nil, err
	}

	return daead.DecryptDeterministically(data, nil) //nolint:wrapcheck // error does not need wrapping
}
