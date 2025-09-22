package encrypt

import (
	"encoding/base64"
	"fmt"
)

// encryptData encrypts the given data and encodes it in base64.
// This is used for line-mode encryption where the output needs to be
// safely represented as a string in the output file.
func (e *Encryptor) encryptData(data []byte) ([]byte, error) {
	if e.Deterministic {
		out, err := e.encryptDeterministic(data)
		if err != nil {
			return nil, err
		}

		envelope := append(newEnvelopeHeader(modeDeterministic), out...)

		return []byte(base64.StdEncoding.EncodeToString(envelope)), nil
	}

	ciphertext, err := e.encryptBytes(data)
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// decryptData decodes the base64 data and decrypts it.
// This is used for line-mode decryption where the input is expected
// to be base64 encoded ciphertext.
func (e *Encryptor) decryptData(data []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}

	if len(ciphertext) < envelopeHeaderSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrProcessing)
	}

	mode, err := parseEnvelopeHeader(ciphertext[:envelopeHeaderSize])
	if err != nil {
		return nil, err
	}

	switch mode {
	case modeDeterministic:
		if len(e.Key) != deterministicKeyLen {
			return nil, fmt.Errorf("%w: deterministic data requires 64-byte key (128 hex chars)", ErrProcessing)
		}

		return e.decryptDeterministic(ciphertext[envelopeHeaderSize:])
	case modeRandomized:
		if len(e.Key) != randomizedKeyLen {
			return nil, fmt.Errorf("%w: randomized data requires 32-byte key (64 hex chars)", ErrProcessing)
		}

		return e.decryptBytes(ciphertext)
	default:
		return nil, fmt.Errorf("%w: unsupported mode", ErrProcessing)
	}
}
