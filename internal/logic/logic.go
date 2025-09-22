// Package logic implements the core business logic for the encryption/decryption.
//
//nolint:cyclop // package complexity is acceptable
package logic

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/idelchi/go-next-tag/pkg/stdin"
	"github.com/idelchi/gocry/internal/config"
	"github.com/idelchi/gocry/internal/encrypt"
	"github.com/idelchi/gogen/pkg/key"
	"github.com/idelchi/gogen/pkg/printer"
)

// Run executes the main encryption/decryption logic based on the provided configuration.
// It handles key loading, input data loading, and processes the data according to the
// specified mode and operation.
//
//nolint:gocognit // function complexity is acceptable
func Run(cfg *config.Config) error {
	var (
		encryptionKey []byte
		err           error
	)

	// Load encryption key either from hex string or file
	switch {
	case cfg.Key.String != "":
		encryptionKey, err = key.FromHex(cfg.Key.String)
	case cfg.Key.File != "":
		encryptionKey, err = os.ReadFile(cfg.Key.File)
		if err != nil {
			return fmt.Errorf("reading key file: %w", err)
		}

		encryptionKey, err = key.FromHex(string(encryptionKey))
	}

	if err != nil {
		return fmt.Errorf("reading key: %w", err)
	}

	const (
		deterministicKeyLen = 64
		normalKeyLen        = 32
	)

	// Ensure key meets requirements depending on operation and mode
	switch cfg.Operation {
	case encrypt.Encrypt:
		if cfg.Deterministic {
			if len(encryptionKey) != deterministicKeyLen {
				return fmt.Errorf("%w: deterministic mode requires 64-byte key (128 hex chars)", config.ErrUsage)
			}
		} else {
			if len(encryptionKey) != normalKeyLen {
				return fmt.Errorf("%w: randomized mode requires 32-byte key (64 hex chars)", config.ErrUsage)
			}
		}
	case encrypt.Decrypt:
		if len(encryptionKey) != deterministicKeyLen && len(encryptionKey) != normalKeyLen {
			return fmt.Errorf("%w: decrypt requires 32- or 64-byte key (64 or 128 hex chars)", config.ErrUsage)
		}
	}

	if cfg.Experiments {
		cfg.Parallel = 1

		if !cfg.Quiet {
			printer.Stderrln("Experimental features enabled: parallel processing disabled")
		}
	}

	// Load input data from stdin or file
	data, err := loadData(cfg.File)
	if err != nil {
		return fmt.Errorf("loading data: %w", err)
	}
	defer data.Close()

	// Initialize encryptor with configuration
	encryptor := &encrypt.Encryptor{
		Key:           encryptionKey,
		Operation:     cfg.Operation,
		Mode:          cfg.Mode,
		Directives:    cfg.Directives,
		Parallel:      cfg.Parallel,
		Deterministic: cfg.Deterministic,
	}

	// Process data and handle any errors
	processed, err := encryptor.Process(data, os.Stdout)
	if err != nil {
		return fmt.Errorf("processing data: %w", err)
	}

	// Print operation summary based on mode
	if !cfg.Quiet {
		if cfg.Mode == "file" {
			printer.Stderrln("%sed file: %q", cfg.Operation, cfg.File)
		}

		if cfg.Mode == "line" && processed {
			printer.Stderrln("%sed lines in: %q", cfg.Operation, cfg.File)
		}
	}

	return nil
}

// loadData returns a file handle for the input data.
func loadData(file string) (*os.File, error) {
	if stdin.IsPiped() {
		return os.Stdin, nil
	}

	data, err := os.Open(filepath.Clean(file))
	if err != nil {
		return nil, fmt.Errorf("opening input file %q: %w", file, err)
	}

	return data, nil
}
