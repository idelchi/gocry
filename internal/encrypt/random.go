package encrypt

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	randomizedMagic   = "GOCRY"
	randomizedVersion = byte(1)
	randomizedTagSize = sha256.Size
)

var randomizedHeaderPrefix = []byte(randomizedMagic)

func randomizedHeader() []byte {
	header := make([]byte, len(randomizedHeaderPrefix)+1)
	copy(header, randomizedHeaderPrefix)
	header[len(randomizedHeaderPrefix)] = randomizedVersion

	return header
}

func parseRandomizedHeader(header []byte) error {
	if len(header) != len(randomizedHeaderPrefix)+1 {
		return fmt.Errorf("%w: header too short", ErrProcessing)
	}

	if !bytes.Equal(header[:len(randomizedHeaderPrefix)], randomizedHeaderPrefix) {
		return fmt.Errorf("%w: invalid header magic", ErrProcessing)
	}

	version := header[len(randomizedHeaderPrefix)]
	if version != randomizedVersion {
		return fmt.Errorf("%w: unsupported version %d", ErrProcessing, version)
	}

	return nil
}

func deriveRandomizedKeys(key []byte) ([]byte, []byte, error) {
	hkdfReader := hkdf.New(sha256.New, key, nil, []byte("gocry/ctr+mac"))
	derived := make([]byte, 64)

	if _, err := io.ReadFull(hkdfReader, derived); err != nil {
		return nil, nil, fmt.Errorf("deriving keys: %w", err)
	}

	return derived[:32], derived[32:], nil
}
