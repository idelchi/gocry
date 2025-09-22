package encrypt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// ErrProcessing indicates an error during processing.
var ErrProcessing = errors.New("processing error")

const (
	deterministicKeyLen = 64
	randomizedKeyLen    = 32
)

// processLines processes each line of the input data in parallel when possible.
// It maintains the original line order in the output while leveraging parallel processing.
// Returns a boolean indicating if any encryption/decryption was performed and any error encountered.
//
//nolint:funlen,gocognit
func (e *Encryptor) processLines(reader io.Reader, writer io.Writer, parallel int) (bool, error) {
	// Read all lines first to maintain output order
	var lines []string

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("%w: scanning error: %w", ErrProcessing, err)
	}

	// Initialize result storage and channels
	results := make([]string, len(lines))
	numWorkers := parallel
	workChan := make(chan int)
	errChan := make(chan error)

	// Track processing status per line
	processedStatus := make([]bool, len(lines))

	var waitGroup sync.WaitGroup

	// Start worker goroutines for parallel processing
	for range numWorkers {
		waitGroup.Add(1)

		go func() {
			defer waitGroup.Done()

			for idx := range workChan {
				line := lines[idx]

				var (
					result       string
					wasProcessed bool
				)

				// Process each line based on operation type and directives
				switch {
				case e.Operation == Encrypt && strings.HasSuffix(line, e.Directives.Encrypt):
					encryptedLine, err := e.encryptData([]byte(line))
					if err != nil {
						errChan <- err

						return
					}

					result = fmt.Sprintf("%s: %s", e.Directives.Decrypt, string(encryptedLine))
					wasProcessed = true

				case e.Operation == Decrypt && strings.HasPrefix(line, e.Directives.Decrypt+": "):
					encryptedData := strings.TrimPrefix(line, e.Directives.Decrypt+": ")

					decryptedLine, err := e.decryptData([]byte(encryptedData))
					if err != nil {
						errChan <- err

						return
					}

					result = string(decryptedLine)
					wasProcessed = true

				default:
					result = line
				}

				results[idx] = result
				processedStatus[idx] = wasProcessed
			}
		}()
	}

	// Distribute work to workers
	go func() {
		for i := range lines {
			workChan <- i
		}

		close(workChan)
	}()

	// Wait for completion and close channels
	go func() {
		waitGroup.Wait()
		close(errChan)
	}()

	// Check for processing errors
	if err := <-errChan; err != nil {
		return false, err
	}

	// Write results maintaining original order
	for _, line := range results {
		if _, err := fmt.Fprintln(writer, line); err != nil {
			return false, fmt.Errorf("%w: writing error: %w", ErrProcessing, err)
		}
	}

	// Check if any line was processed
	anyProcessed := false

	for _, processed := range processedStatus {
		if processed {
			anyProcessed = true

			break
		}
	}

	return anyProcessed, nil
}

// processWholeFile processes the entire input as a single block of data.
// It's used when line-by-line processing is not required.
// Returns true if processing was performed and any error encountered.
//
//nolint:gocognit	// function complexity is acceptable
func (e *Encryptor) processWholeFile(reader io.Reader, writer io.Writer) (bool, error) {
	switch e.Operation {
	case Encrypt:
		if e.Deterministic {
			header := newEnvelopeHeader(modeDeterministic)
			if _, err := writer.Write(header); err != nil {
				return false, fmt.Errorf("writing header: %w", err)
			}

			buf, err := io.ReadAll(reader)
			if err != nil {
				return false, fmt.Errorf("reading input: %w", err)
			}

			out, err := e.encryptDeterministic(buf)
			if err != nil {
				return false, err
			}

			_, err = writer.Write(out)

			return true, err //nolint:wrapcheck // error does not need wrapping
		}

		return true, e.encryptStream(reader, writer)
	case Decrypt:
		header := make([]byte, envelopeHeaderSize)
		if _, err := io.ReadFull(reader, header); err != nil {
			return false, fmt.Errorf("reading header: %w", err)
		}

		mode, err := parseEnvelopeHeader(header)
		if err != nil {
			return false, err
		}

		switch mode {
		case modeDeterministic:
			if len(e.Key) != deterministicKeyLen {
				return false, fmt.Errorf("%w: deterministic data requires 64-byte key (128 hex chars)", ErrProcessing)
			}

			e.Deterministic = true

			buf, err := io.ReadAll(reader)
			if err != nil {
				return false, fmt.Errorf("reading ciphertext: %w", err)
			}

			out, err := e.decryptDeterministic(buf)
			if err != nil {
				return false, err
			}

			_, err = writer.Write(out)

			return true, err //nolint:wrapcheck // error does not need wrapping
		case modeRandomized:
			if len(e.Key) != randomizedKeyLen {
				return false, fmt.Errorf("%w: randomized data requires 32-byte key (64 hex chars)", ErrProcessing)
			}

			e.Deterministic = false

			return true, e.decryptStream(reader, writer, header)
		default:
			return false, fmt.Errorf("%w: invalid header mode", ErrProcessing)
		}
	}

	return false, fmt.Errorf("%w: invalid operation", ErrProcessing)
}
