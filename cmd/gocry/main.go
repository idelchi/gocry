package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/idelchi/go-encryptor/internal/encrypt"
)

// Global variable for CI stamping.
var version = "unknown - unofficial & generated by unknown"

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)

		os.Exit(1)
	}

	key, err := os.ReadFile(cfg.Key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading key file: %v\n", err)
		os.Exit(1)
	}

	if cfg.GPG {
		key, err = deriveKeyFromGPG(string(key))
		if err != nil {
			fmt.Fprintf(os.Stderr, "deriving key from GPG: %v\n", err)
			os.Exit(1)
		}
	}

	// Open the input file
	inputFile, err := os.Open(cfg.File)
	if err != nil {
		fmt.Fprintf(os.Stderr, "opening input file %q: %v\n", cfg.File, err)
		os.Exit(1)
	}
	defer inputFile.Close()

	// Use os.Stdout as the writer
	processed, err := encrypt.Process(cfg.Mode, cfg.Operation, cfg.Type, key, inputFile, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error processing data: %v\n", err)
		os.Exit(1)
	}
	if cfg.Mode == "file" {
		fmt.Fprintf(os.Stderr, "%sed file: %q\n", cfg.Operation, cfg.File)
	}

	if cfg.Mode == "line" && processed {
		fmt.Fprintf(os.Stderr, "%sed lines in: %q\n", cfg.Operation, cfg.File)
	}
}

func deriveKeyFromGPG(gpgKey string) ([]byte, error) {
	gpgKeyDecoded, err := base64.StdEncoding.DecodeString(gpgKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 gpg key: %w", err)
	}

	// Use SHA-256 to derive a 32-byte key for AES-256
	hash := sha256.Sum256(gpgKeyDecoded)
	return hash[:], nil
}
