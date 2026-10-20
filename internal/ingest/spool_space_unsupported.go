//go:build !linux && !darwin

package ingest

import (
	"errors"
	"os"
)

func spoolFilesystemSpace(*os.File) (spoolSpace, error) {
	return spoolSpace{}, errors.New("filesystem headroom observation requires Linux or macOS")
}
