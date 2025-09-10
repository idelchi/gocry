package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// encryptStream encrypts data from reader to writer using AES-CTR mode.
// It prepends the randomly generated IV to the encrypted output.
// The encryption is done in chunks to maintain constant memory usage.
func (e *Encryptor) encryptStream(reader io.Reader, writer io.Writer) error {
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	// Generate a random IV (Initialization Vector)
	initializationVector := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, initializationVector); err != nil {
		return fmt.Errorf("generating IV: %w", err)
	}

	// Write IV directly
	if _, err := writer.Write(initializationVector); err != nil {
		return fmt.Errorf("writing IV: %w", err)
	}

	stream := cipher.NewCTR(block, initializationVector)
	// Use fixed-size buffers for reading and encryption
	const bufferSize = 4096

	buf := make([]byte, bufferSize)
	encrypted := make([]byte, bufferSize)

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			stream.XORKeyStream(encrypted[:n], buf[:n])

			if _, errWrite := writer.Write(encrypted[:n]); errWrite != nil {
				return fmt.Errorf("writing encrypted data: %w", errWrite)
			}
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("reading data: %w", err)
		}
	}

	return nil
}

// decryptStream decrypts data from reader to writer using AES-CTR mode.
// It expects the IV to be prepended to the encrypted data.
// The decryption is done in chunks to maintain constant memory usage.
func (e *Encryptor) decryptStream(reader io.Reader, writer io.Writer) error {
	// Read the prepended IV
	initializationVector := make([]byte, aes.BlockSize)

	n, err := io.ReadFull(reader, initializationVector)
	if err != nil {
		return fmt.Errorf("reading IV: %w", err)
	}

	if n < aes.BlockSize {
		return fmt.Errorf("%w: IV too short", ErrProcessing)
	}

	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	stream := cipher.NewCTR(block, initializationVector)
	// Use fixed-size buffers for reading and decryption
	const bufferSize = 4096

	buf := make([]byte, bufferSize)
	decrypted := make([]byte, bufferSize)

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			stream.XORKeyStream(decrypted[:n], buf[:n])

			if _, errWrite := writer.Write(decrypted[:n]); errWrite != nil {
				return fmt.Errorf("writing decrypted data: %w", errWrite)
			}
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("reading encrypted data: %w", err)
		}
	}

	return nil
}

// encryptDeterministic encrypts the entire data buffer deterministically using AES-SIV.
func (e *Encryptor) encryptDeterministic(data []byte) ([]byte, error) {
	daead, err := newDAEAD(e.Key)
	if err != nil {
		return nil, err
	}

	return daead.EncryptDeterministically(data, nil) //nolint:wrapcheck	// error does not need wrapping
}

// decryptDeterministic decrypts data previously encrypted with AES-SIV.
func (e *Encryptor) decryptDeterministic(data []byte) ([]byte, error) {
	daead, err := newDAEAD(e.Key)
	if err != nil {
		return nil, err
	}

	return daead.DecryptDeterministically(data, nil) //nolint:wrapcheck	// error does not need wrapping
}
