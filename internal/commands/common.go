package commands

import (
	"fmt"

	"github.com/idelchi/gocry/internal/config"
	"github.com/idelchi/gogen/pkg/cobraext"
)

func setFileAndValidate(cfg *config.Config, args []string) error {
	arg, err := cobraext.PipeOrArg(args)
	if err != nil {
		return fmt.Errorf("reading password: %w", err)
	}

	cfg.File = arg

	if err := cobraext.Validate(cfg, cfg); err != nil {
		return fmt.Errorf("validating configuration: %w", err)
	}

	return nil
}