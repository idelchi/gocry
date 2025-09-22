package encrypt

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	envelopeMagic   = "GOCRY"
	envelopeVersion = byte(1)
	envelopeTagSize = sha256.Size
)

type envelopeMode byte

const (
	modeDeterministic envelopeMode = 0x01
	modeRandomized    envelopeMode = 0x02
)

//nolint:gochecknoglobals // these globals are acceptable
var envelopeHeaderPrefix = []byte(envelopeMagic)

const envelopeHeaderSize = len(envelopeMagic) + 2

func newEnvelopeHeader(mode envelopeMode) []byte {
	header := make([]byte, envelopeHeaderSize)

	copy(header, envelopeHeaderPrefix)

	header[len(envelopeHeaderPrefix)] = envelopeVersion
	header[len(envelopeHeaderPrefix)+1] = byte(mode)

	return header
}

func parseEnvelopeHeader(header []byte) (envelopeMode, error) {
	if len(header) != envelopeHeaderSize {
		return 0, fmt.Errorf("%w: header too short", ErrProcessing)
	}

	if !bytes.Equal(header[:len(envelopeHeaderPrefix)], envelopeHeaderPrefix) {
		return 0, fmt.Errorf("%w: invalid header magic", ErrProcessing)
	}

	version := header[len(envelopeHeaderPrefix)]
	if version != envelopeVersion {
		return 0, fmt.Errorf("%w: unsupported version %d", ErrProcessing, version)
	}

	mode := envelopeMode(header[len(envelopeHeaderPrefix)+1])
	switch mode {
	case modeDeterministic, modeRandomized:
		return mode, nil
	default:
		return 0, fmt.Errorf("%w: unsupported mode %d", ErrProcessing, mode)
	}
}

func deriveRandomizedKeys(key []byte) ([]byte, []byte, error) {
	const (
		hkdfOutputLen       = 64
		randomizedEncKeyLen = 32
		randomizedMacKeyLen = 32
	)

	hkdfReader := hkdf.New(sha256.New, key, nil, []byte("gocry/ctr+mac"))
	derived := make([]byte, hkdfOutputLen)

	if _, err := io.ReadFull(hkdfReader, derived); err != nil {
		return nil, nil, fmt.Errorf("deriving keys: %w", err)
	}

	return derived[:randomizedEncKeyLen], derived[randomizedEncKeyLen:], nil
}
